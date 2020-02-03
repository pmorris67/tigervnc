/* Copyright 2019 Philip Morris
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307,
 * USA.
 */

#include "SshConnectionSocket.h"
#include <rdr/Exception.h>
#include <rfb/LogWriter.h>

#include <afunix.h>

#include <cstdio>
#include <cstdlib>

#define MAXSERVERNAMELEN 256

static rfb::LogWriter vlog("SshConnectionSocket");

SshConnectionSocket* SshConnectionSocket::create(const char* vncServerName,
	SshConnectionCallback* callback) {
  SshConnectionSocket* sock = NULL;
  
  // Look for ssh connection request who@where:[port,path]
  char sshUserName[MAXSERVERNAMELEN] = { 0 };
  char sshServerName[MAXSERVERNAMELEN] = { 0 };
  char sshSocketName[PATH_MAX] = { 0 };
  const char* sshServerNameDelim = strchr(vncServerName, '@');

  if (sshServerNameDelim != 0) {
  	int remotePort = 5900;
  	
    strncpy(sshUserName, vncServerName, sshServerNameDelim - vncServerName);

	// Find port or path
    const char* vncServerDisplayDelim = strchr(sshServerNameDelim+1, ':');
    if (vncServerDisplayDelim != 0) {
      strncpy(sshServerName, sshServerNameDelim+1, vncServerDisplayDelim - (sshServerNameDelim+1));
      
      char* vncServerDisplayEnd = 0;
      int display = strtol(vncServerDisplayDelim + 1, &vncServerDisplayEnd, 10);
      if ((vncServerDisplayDelim + 1) != vncServerDisplayEnd) {
        remotePort = 5900 + display;
      } else {
		// For convenience we assume relative paths are in the user's
		// .vnc directory.
		if (vncServerDisplayDelim[1] != '/') {
		  snprintf(sshSocketName, PATH_MAX, "/home/%s/.vnc/%s",
				sshUserName, vncServerDisplayDelim + 1);
		} else {
		  strncpy(sshSocketName, vncServerDisplayDelim + 1, PATH_MAX);
		}
      }
    } else {
      strncpy(sshServerName, sshServerNameDelim+1, MAXSERVERNAMELEN);
	}

    vlog.debug("SSH %s %s", sshUserName, sshServerName);

    ssh_session ss = ssh_new();
    if (ss == NULL) {
      throw rdr::Exception("failed to connect SSH session");
    }

    ssh_options_set(ss, SSH_OPTIONS_HOST, sshServerName);
    ssh_options_set(ss, SSH_OPTIONS_USER, sshUserName);

    int rc = ssh_connect(ss);
    if (SSH_OK != rc) {
      throw rdr::Exception("failed to connect SSH connection");
    }
    
//    ssh_options_set(ss, SSH_OPTIONS_KEY_EXCHANGE, "");

	rc = ssh_session_is_known_server(ss);
    bool trusted_server = rc != SSH_SERVER_NOT_KNOWN;
    
    // Check to see if the user wants to trust this server
    if (!trusted_server) {
      ssh_key key;
      if (SSH_OK == ssh_get_server_publickey(ss, &key)) {
		// Display hash of server's key in the same form as OpenSSH
		unsigned char* hash = 0;
		size_t hash_size = 0;
		ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA256, &hash, &hash_size);
        char* key_hash_str = ssh_get_fingerprint_hash(SSH_PUBLICKEY_HASH_SHA256, hash, hash_size);
        if (key_hash_str) {
		  const char* key_type = ssh_key_type_to_char(ssh_key_type(key));
		  if (callback && callback->addServerToKnownHosts(sshServerName, key_type, key_hash_str)) {
		    trusted_server = true;
		  }	
		  ssh_string_free_char(key_hash_str);
		}
        ssh_clean_pubkey_hash(&hash);
        ssh_key_free(key);
	  }
	}
	
	// Do we trust the server now?
	if (trusted_server) {
      vlog.debug("Write known SSH server");
      ssh_session_update_known_hosts(ss);
    } else {
	  throw rdr::Exception("unknown SSH server");
    }

    rc = ssh_userauth_publickey_auto(ss, NULL, NULL);
    if (rc == SSH_AUTH_ERROR) {
      throw rdr::Exception("failed SSH public key authentication");
    }
    vlog.debug("Authorised");

    ssh_channel ssc = ssh_channel_new(ss);
    if (ssc == NULL) {
      throw rdr::Exception("failed to create SSH channel");
    }

    if (sshSocketName[0] != 0) {
      vlog.debug("Opening remote socket %s", sshSocketName);
      rc = ssh_channel_open_forward_unix(ssc, sshSocketName, "localhost", 0);
      if (rc != SSH_OK) {
        throw rdr::Exception("failed to open forward unix socket channel");
      }
    } else {
      vlog.debug("Opening remote port %d", remotePort);
      rc = ssh_channel_open_forward(ssc, "localhost", remotePort, "localhost", 0);
      if (rc != SSH_OK) {
        throw rdr::Exception("failed to open forward TCP channel");
      }
    }
    
    if (ssh_channel_is_open(ssc)) {
      int socks[2] = { 0 };
      int rc = socketpair(AF_UNIX, SOCK_STREAM, 0, socks);
		if (rc == 0) {
			sock = new SshConnectionSocket(ss, ssc, socks);
		} else {
          throw rdr::Exception("failed to open local socket pair");
		}
      vlog.debug("Created SSH tunnel\n");
	} else {
      throw rdr::Exception("failed to complete forward channel");
	}

    if (sock == NULL) {
      ssh_channel_close(ssc);
      ssh_channel_free(ssc);
      ssh_disconnect(ss);
      ssh_free(ss);
    }
  }

  return sock;
}

SshConnectionSocket::SshConnectionSocket(ssh_session ss, ssh_channel ch, int sockpair[2])
	: TcpSocket(sockpair[1]), session(ss), channel(ch), socket(sockpair[0]), thread(0) {
	stop = false;
	pthread_create(&thread, NULL, &SshConnectionSocket::main_static, this);
}

SshConnectionSocket::~SshConnectionSocket() {
	stop = true;
	pthread_join(thread, NULL);
}

void* SshConnectionSocket::main_static(void* arg) {	
  SshConnectionSocket* sst = (SshConnectionSocket*) arg;
  return sst->main();
}

void* SshConnectionSocket::main() {
  while (!stop)
  {
  	ssh_channel in_channels[2] = { channel, NULL };
  	ssh_channel out_channels[2] = { NULL };
  	fd_set rdfds;
  	FD_ZERO(&rdfds);
  	FD_SET(socket, &rdfds);
  	
  	struct timeval tv = { 1, 0 };
  	int rc = ssh_select(in_channels, out_channels, socket+1, &rdfds, &tv);
  	
  	if (rc == SSH_OK) {
  	  if (out_channels[0] != NULL) {
        char buf[4096];
        int rd = ssh_channel_read_nonblocking(channel, buf, sizeof(buf), 0); 
        if (rd > 0) {
          // Blocking write to socket
          ::write(socket, buf, rd);
		} 	  
  	  }
  	  
  	  if (FD_ISSET(socket, &rdfds)) {
        char buf[4096];
        int rd = recv(socket, buf, sizeof(buf), MSG_DONTWAIT);
        if (rd > 0) {
          // Blocking write to socket
          ssh_channel_write(channel, buf, rd);      
        }
  	  }
  	} else if (rc == SSH_ERROR) {
      stop = true;
	}
  }
  
  // Clear up here
  ssh_channel_close(channel);
  ssh_channel_free(channel);
  ssh_disconnect(session);
  ssh_free(session);    
  ::close(socket);
  
  return 0;
}
