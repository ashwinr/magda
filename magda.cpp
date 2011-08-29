#include <vector>
#include <fstream>
#include <sstream>
#include <iostream>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <curl/curl.h>
#include <libspotify/api.h>

#include "magda.h"
#include "rapidxml.hpp"
#include "rapidxml_utils.hpp"

namespace {

using namespace rapidxml;

sp_session* sp;
pthread_cond_t s_cond;
pthread_mutex_t s_mutex;
volatile bool s_notified = false;

const long HTTP_OK = 200;
const std::string playlist_name = "pandora";

size_t curl_response(char *ptr, size_t size, size_t nmemb, void *userdata)
{
  if(!userdata) return 0;
  
  std::string* buffer = static_cast<std::string*>(userdata);
  (*buffer) += std::string(ptr, size*nmemb);
  return size*nmemb;
}

CURLcode getPandoraBookmarks(const std::string& user, std::string* page)
{
  static const std::string base_url = "http://feeds.pandora.com/feeds/people/";
  
  if(!page) return CURLE_FAILED_INIT;

  CURL* curl = curl_easy_init();
  if(!curl) return CURLE_FAILED_INIT;

  char* c_user = curl_easy_escape(curl, user.c_str(), user.length());
  std::string url = base_url + c_user + "/favorites.xml";
  std::string header;

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, page);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &curl_response);

  CURLcode ret = curl_easy_perform(curl);
  if(ret == 0)
  {
    long http_rcode;
    ret = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_rcode);
    if(http_rcode != HTTP_OK)
    {
      (*page) = "";
      ret = CURLE_COULDNT_RESOLVE_HOST;
    }
  }

  curl_free(c_user);
  curl_easy_cleanup(curl);
  return ret;
}

int getPandoraSongs(std::string xml, std::vector<Song>* songs)
{
  try
  {
    xml_document<> doc;
    char* xml_buffer = const_cast<char*>(xml.c_str());
    doc.parse<0>(xml_buffer);

    xml_node<>* item_node = doc.first_node("rss"); if(!item_node) return -1;
    item_node = item_node->first_node("channel");  if(!item_node) return -1;
    item_node = item_node->first_node("item");     if(!item_node) return -1;

    while(item_node)
    {
      Song s;
      xml_node<>* node;

      //guid
      node = item_node->first_node("guid"); if(!node) return -1;
      s.guid = node->value();
      //title
      node = item_node->first_node("mm:Track"); if(!node) return -1;
      node = node->first_node("dc:title"); if(!node) return -1;
      s.title = node->value();
      //artist
      node = item_node->first_node("mm:Artist"); if(!node) return -1;
      node = node->first_node("dc:title"); if(!node) return -1;
      s.artist = node->value();
      //album
      node = item_node->first_node("mm:Album"); if(!node) return -1;
      node = node->first_node("dc:title"); if(!node) return -1;
      s.album = node->value();

      songs->push_back(s);
      item_node = item_node->next_sibling("item");
    }
  }
  catch(const std::exception& e) { return -1; }

  return 0;
}

void logged_in(sp_session *sess, sp_error error)
{  
  if(error != SP_ERROR_OK)
  {
    std::cerr << "Unable to login: " << sp_error_message(error) << std::endl;
    sp_session_release(sp);    
    exit(-1);
  }
  
  sp_playlistcontainer* pc = sp_session_playlistcontainer(sess);

  std::cout << "logged_in: " << sp_playlistcontainer_num_playlists(pc) << std::endl;

	for (int i=0; i<sp_playlistcontainer_num_playlists(pc); i++)
	{
		sp_playlist* pl = sp_playlistcontainer_playlist(pc, i);
    std::cout << sp_playlist_name(pl) << std::endl;
	}


}

void metadata_updated(sp_session* sess)
{
  
}

void connection_error(sp_session *sess, sp_error error)
{
  
}

void notify_main_thread(sp_session* sess)
{
//  std::cout << "notify_main_thread" << std::endl;
  
  pthread_mutex_lock(&s_mutex);
  s_notified = true;
  pthread_cond_signal(&s_cond);
  pthread_mutex_unlock(&s_mutex);
}

}

int main(int argc, char** argv)
{
  int ret;
  std::string p_user(""), s_apikey_file("");
  std::string s_user(""), s_password("");
  
  while((ret = getopt(argc, argv, "n:k:u:p:h")) != -1)
    switch(ret)
    {
      case 'n':
        p_user = optarg;
        break;
      case 'k':
        s_apikey_file = optarg;
        break;
      case 'u':
        s_user = optarg;
        break;
      case 'p':
        s_password = optarg;
        break;
      case 'h':
        std::cout << "usage: " << std::endl;
        break;
    }

    // If any of user/apikey/creds/timeout are unset, leave right now and never come back
    if(p_user == "" || s_apikey_file == "" || s_user == "" || s_password == "")
      return -1;

    // Load the spotify api key
    char spotify_key[1024];
    std::ifstream ifs(s_apikey_file.c_str(), std::ios_base::binary);
    if(ifs.fail())
    {
      std::cout << "Unable to open api-key file '" << s_apikey_file << "'" << std::endl;
      return -1;
    }

    ifs.read(spotify_key, 1024);
    if(ifs.bad() || (ifs.fail() && !ifs.eof()))
    {
      std::cout << "Unable to read api-key file '" << s_apikey_file
                << "'" << std::endl;
      ifs.close();
      return -1;
    }
    std::streamsize spotify_key_len = ifs.gcount();
    ifs.close();

    // Fetch the user's pandora bookmarks feed
    std::string feed;
    if(getPandoraBookmarks(p_user, &feed))
    {
      std::cerr << "Unable to get Pandora bookmarks for user '"
                << p_user << "'" << std::endl;
      return -1;
    }

    // Fetch songs
    std::vector<Song> songs;
    if(getPandoraSongs(feed, &songs) || songs.size() < 1)
    {
      std::cerr << "Unable to get songs for user '" << p_user << "'" << std::endl;
      return -1;
    }

    // Create a cache directory
    std::string tmp_dir = "/var/tmp/" + p_user;
    if(mkdir(tmp_dir.c_str(), S_IRWXU | S_IRWXG | S_IRWXO) != 0 && errno != EEXIST)
    {
      std::cerr << "Unable to create spotify cache at '" + tmp_dir
                << "' : " << errno << std::endl;
      return -1;
    }

    // Login to spotify
    sp_session_callbacks session_callbacks = {
      &logged_in,
    	NULL,
    	&metadata_updated,
    	&connection_error,
    	NULL,
    	&notify_main_thread,
    	NULL, NULL, NULL, NULL, NULL,
    	NULL, NULL, NULL, NULL, NULL
    };

    sp_session_config spconfig = {
      SPOTIFY_API_VERSION,
    	tmp_dir.c_str(),
    	tmp_dir.c_str(),
    	static_cast<void*>(spotify_key),
    	spotify_key_len,
    	"magda",
    	&session_callbacks,
    	NULL,
    };

    sp_error err;
    int timeout = 0;

    err = sp_session_create(&spconfig, &sp);
    if(err != SP_ERROR_OK)
    {
      std::cerr << "Unable to connect to spotify: "
                << sp_error_message(err) << std::endl;
      return -1;
    }

    sp_session_login(sp, s_user.c_str(), s_password.c_str());

    pthread_mutex_init(&s_mutex, NULL);
    pthread_cond_init(&s_cond, NULL);
    
    while(1)
    {
      while(s_notified == false)
      {
        pthread_mutex_lock(&s_mutex);
        
        if(timeout == 0)
          pthread_cond_wait(&s_cond, &s_mutex);
        else
        {
          struct timespec ts;
    			struct timeval tv;

    			gettimeofday(&tv, NULL);
    			TIMEVAL_TO_TIMESPEC(&tv, &ts);
          ts.tv_sec += timeout / 1000;
    			ts.tv_nsec += (timeout % 1000) * 1000000;

          pthread_cond_timedwait(&s_cond, &s_mutex, &ts);
        }

        pthread_mutex_unlock(&s_mutex);        
      }

      do
      {
        sp_session_process_events(sp, &timeout);
      } while(timeout == 0);

      pthread_mutex_lock(&s_mutex);
      s_notified = false;
      pthread_mutex_unlock(&s_mutex);
    }

    sp_session_release(sp);    
    return 0;
}
