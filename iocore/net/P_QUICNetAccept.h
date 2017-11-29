/** @file

  A brief file description

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#pragma once

#include "ts/ink_platform.h"

//
// QUICNetAccept
// Handles accepting connections.
//
struct QUICNetAccept : public Continuation {
  explicit QUICNetAccept();
  virtual ~QUICNetAccept();

  virtual NetProcessor *getNetProcessor() const;

  virtual void init_accept_per_thread();

  virtual int mainEvent(int event, void *e);


  void process_long_header_packets();
  void process_short_header_packets();
  void process_newconn();

  EThread *thread;
  // Atomic Queue to save Long Header Packet
  ASLL(UDPPacketInternal, alink) longInQueue;
  // Atomic Queue to save Short Header Packet
  ASLL(UDPPacketInternal, alink) shortInQueue;
  // Internal Queue to save 0-RTT Packet
  Que(UDPPacket, link) zeroRTTQueue;

private:
  Map<int64_t, QUICNetVConnection *> _connections;
};

static inline QUICNetAccept *
get_QUICNetAccept(EThread *t) 
{
  return (QUICNetAccept *)ETHREAD_GET_PTR(t, quic_NetProcessor.quicNetAccept_offset);
}
