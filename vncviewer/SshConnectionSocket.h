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

#ifndef __SSHCHANNELTHREAD_H__
#define __SSHCHANNELTHREAD_H__

#include "network/TcpSocket.h"

#include <libssh/libssh.h>
#include <pthread.h>

class SshConnectionSocket : public network::TcpSocket
{
public:

	class SshConnectionCallback {
	public:
		virtual bool addServerToKnownHosts(const char* hostname,
			const char* key_type,
			const char* key_hash) = 0;
	};

	// Factory function
	static SshConnectionSocket* create(const char* vncServerName, SshConnectionCallback* callback);

	virtual ~SshConnectionSocket();
	
	virtual bool isSecure() { return true; }
	
private:

	SshConnectionSocket(ssh_session ss, ssh_channel ch, int sockpair[2]);

	ssh_session session;
	ssh_channel channel;
	int socket;
	volatile bool stop;
	pthread_t thread;

	static void* main_static(void* arg);
	void* main(); 
};

#endif

