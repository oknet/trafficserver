/** @file

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

#include "ts/ink_config.h"
#include "P_Net.h"

#include "QUICConfig.h"
#include "QUICPacket.h"
#include "QUICDebugNames.h"
#include "QUICEvents.h"

QUICPacketHandler::QUICPacketHandler(const NetProcessor::AcceptOptions &opt) : NetAccept(opt)
{
  this->mutex = new_ProxyMutex();
}

QUICPacketHandler::~QUICPacketHandler()
{
}

NetProcessor *
QUICPacketHandler::getNetProcessor() const
{
  return &quic_NetProcessor;
}

NetAccept *
QUICPacketHandler::clone() const
{
  NetAccept *na;
  na  = new QUICPacketHandler(opt);
  *na = *this;
  return na;
}

int
QUICPacketHandler::acceptEvent(int event, void *data)
{
  // NetVConnection *netvc;
  ink_release_assert(event == NET_EVENT_DATAGRAM_OPEN || event == NET_EVENT_DATAGRAM_READ_READY ||
                     event == NET_EVENT_DATAGRAM_ERROR);
  ink_release_assert((event == NET_EVENT_DATAGRAM_OPEN) ? (data != nullptr) : (1));
  ink_release_assert((event == NET_EVENT_DATAGRAM_READ_READY) ? (data != nullptr) : (1));

  if (event == NET_EVENT_DATAGRAM_OPEN) {
    // Nothing to do.
    return EVENT_CONT;
  } else if (event == NET_EVENT_DATAGRAM_READ_READY) {
    Queue<UDPPacket> *queue = (Queue<UDPPacket> *)data;
    UDPPacket *packet_r;
    int n = eventProcessor.thread_group[ET_QUIC]._count;
    while ((packet_r = queue->dequeue())) {
      uint8_t *buf = (uint8_t *)packet_r->getIOBlockChain()->buf();
      if (buf[0] & 0x80 && 1 <= (buf[0] & 0x7f) && (buf[0] & 0x7f) <= 5) {
        // Long Header Packet with Connection ID, has a valid type value.
        // Get QUICNetAccept by Hash(Source IP & Port)
        uint32_t v        = ats_ip_port_hash(&packet_r->from.sa);
        EThread *t        = eventProcessor.thread_group[ET_QUIC]._thread[v % n];
        QUICNetAccept *na = get_QUICNetAccept(t);
        na->longInQueue.push((UDPPacketInternal *)packet_r);
      } else if (buf[0] & 0x40 && 1 <= (buf[0] & 0x1f) && (buf[0] & 0x1f) <= 3) {
        // Short Header Packet with Connection ID, has a valid type value.
        // Get QUICNetAccept by Hash(QUIC Connection ID)
		uint64_t v        = QUICTypeUtil::read_QUICConnectionId(buf + 1, 8);
        EThread *t        = eventProcessor.thread_group[ET_QUIC]._thread[v % n];
        QUICNetAccept *na = get_QUICNetAccept(t);
        na->shortInQueue.push((UDPPacketInternal *)packet_r);
      } else if (1 <= (buf[0] & 0x1f) && (buf[0] & 0x1f) <= 3) {
        // Short Header Packet without Connection ID, has a valid type value.
        // TODO: Assign Connection ID by rules
        ip_port_text_buffer ipb;
        Debug("quic_sec", "Received a short header packet without ConnID from %s, size=%" PRId64,
              ats_ip_nptop(&packet_r->from.sa, ipb, sizeof(ipb)), packet_r->getPktLength());
        packet_r->free();
      } else {
        ip_port_text_buffer ipb;
        Debug("quic_sec", "Received a bad packet from %s, size=%" PRId64, ats_ip_nptop(&packet_r->from.sa, ipb, sizeof(ipb)),
              packet_r->getPktLength());
        packet_r->free();
      }
    }
    return EVENT_CONT;
  }

  /////////////////
  // EVENT_ERROR //
  /////////////////
  if (((long)data) == -ECONNABORTED) {
  }

  ink_abort("QUIC accept received fatal error: errno = %d", -((int)(intptr_t)data));
  return EVENT_CONT;
  return 0;
}

void
QUICPacketHandler::init_accept(EThread *t = nullptr)
{
  SET_HANDLER(&QUICPacketHandler::acceptEvent);
}
