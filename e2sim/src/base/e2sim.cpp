/*****************************************************************************
#                                                                            *
# Copyright 2020 AT&T Intellectual Property                                  *
# Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved.      *
#                                                                            *
# Licensed under the Apache License, Version 2.0 (the "License");            *
# you may not use this file except in compliance with the License.           *
# You may obtain a copy of the License at                                    *
#                                                                            *
#      http://www.apache.org/licenses/LICENSE-2.0                            *
#                                                                            *
# Unless required by applicable law or agreed to in writing, software        *
# distributed under the License is distributed on an "AS IS" BASIS,          *
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   *
# See the License for the specific language governing permissions and        *
# limitations under the License.                                             *
#                                                                            *
******************************************************************************/

#include <cstdio>
#include <unistd.h>
#include <string>
#include <iostream>
#include <vector>
#include <map>
#include <list>
#include <set>

#include "e2sim.hpp"
#include "e2sim_defs.h"
#include "e2sim_sctp.hpp"
#include "e2ap_message_handler.hpp"
#include "encode_e2apv1.hpp"
#include "signal_handler.hpp"

#include "all_handovers_plmn.h"
#include "handover_item.h"
#include "handover_list.h"
#include "all_handovers.h"
#include "control_message_encoder_decoder.h"
#include "cell_handovers_list.h"
#include "ProtocolIE-SingleContainer.h"

#include "RICindication.h"
#include "InitiatingMessage.h"
#include "ProtocolIE-Field.h"
#include "E2AP-PDU.h"
#include "E2SM-KPM-IndicationMessage.h"

#include <cstring>
#include <getopt.h>
#include <sys/time.h>
#include <time.h>
#include <sstream>
#include <string>

using namespace std;

// modified
char* converHexToByteLocal(std::string hexString) {

    char * bytes = new char[hexString.length()/2];
    std::stringstream converter;

    for(int i = 0; i < hexString.length(); i+=2)
    {
        converter << std::hex << hexString.substr(i,2);
        int byte;
        converter >> byte;
        bytes[i/2] = byte & 0xFF;
        converter.str(std::string());
        converter.clear();
    }
    // char* bytesPointer= bytes;
    // return bytesPointer;
    return bytes;
}  
// end modificaion

std::unordered_map<long , OCTET_STRING_t*> E2Sim::getRegistered_ran_functions() {
  return ran_functions_registered;
}

void E2Sim::register_subscription_callback(long func_id, SubscriptionCallback cb) {
  LOG_I("%%%%about to register callback for subscription for func_id %ld", func_id);
  subscription_callbacks[func_id] = cb;
}

SubscriptionCallback E2Sim::get_subscription_callback(long func_id) {
  LOG_I("%%%%we are getting the subscription callback for func id %ld", func_id);
  SubscriptionCallback cb;

  try {
    cb = subscription_callbacks.at(func_id);
  } catch(const std::out_of_range& e) {
    throw std::out_of_range("Function ID is not registered");
  }
  return cb;
}

void E2Sim::register_sm_callback(long func_id, SmCallback cb) {
    LOG_I("%%%%about to register callback for e2sm for func_id %ld", func_id);
    sm_callbacks[func_id] = cb;
}

SmCallback E2Sim::get_sm_callback(long func_id) {
    LOG_I("%%%%we are getting the e2sm callback for func id %ld\n", func_id);
    SmCallback cb;
    try {
        cb = sm_callbacks.at(func_id);
    } catch (const std::out_of_range &e) {
        LOG_E("Function ID is not registered");
        throw std::out_of_range("Function ID is not registered");
    }
    return cb;
}

void E2Sim::register_e2sm(long func_id, OCTET_STRING_t *ostr) {

  //Error conditions:
  //If we already have an entry for func_id

  LOG_I("%%%%about to register e2sm func desc for %ld\n", func_id);

  ran_functions_registered[func_id] = ostr;

}

void E2Sim::encode_and_send_sctp_data(E2AP_PDU_t* pdu)
{
  // print pdu
  // InitiatingMessage_t* initMsg; 
  // if(pdu->present == E2AP_PDU_PR_initiatingMessage){
  //   std::cout << "enc 1" << std::endl;
  //   initMsg = pdu->choice.initiatingMessage;
  //   // std::cout << "Pringing the init msg encode_and_send_sctp_data " << std::endl;
  //   // xer_fprint(stdout, &asn_DEF_InitiatingMessage, initMsg);
  //   RICindication_t* ricIndication = &initMsg->value.choice.RICindication;
  //   // xer_fprint(stdout, &asn_DEF_RICindication, ricIndication);
  //   for (uint8_t idx = 0; idx < ricIndication->protocolIEs.list.count; idx++)
  //   {
      
  //       RICindication_IEs *ie = ricIndication->protocolIEs.list.array [idx];
  //       // std::cout << "enc 2 " << ie->id << std::endl;
  //       switch(ie->value.present)
  //       {
  //           case RICindication_IEs__value_PR_RICindicationMessage:  // RIC indication message
  //           {
  //             // std::cout << "enc 3" << std::endl;
  //               int payload_size = ie->value.choice.RICindicationMessage.size;
  //               char* payload = (char*) calloc(payload_size, sizeof(char));
  //               memcpy(payload, ie->value.choice.RICindicationMessage.buf, payload_size);
  //               E2SM_KPM_IndicationMessage_t *descriptor = 0;
  //               auto retvalMsgKpm = asn_decode(nullptr, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_IndicationMessage, (void **) &descriptor, payload, payload_size);
  //               // std::cout << "priting the ind msg" << std::endl;
  //               // xer_fprint(stdout, &asn_DEF_E2SM_KPM_IndicationMessage, descriptor);
  //               free(payload);
  //               break;
  //           }
  //       }
  //   }
  // }

  uint8_t       *buf;
  sctp_buffer_t data;

  data.len = e2ap_asn1c_encode_pdu(pdu, &buf);
  memcpy(data.buffer, buf, min(data.len, MAX_SCTP_BUFFER));

  int sent_size = sctp_send_data(client_fd, data);
  

  char printBuffer[40960]{};
  char *tmp = printBuffer;
  for (size_t i = 0; i < (size_t)data.len; ++i) {
      snprintf(tmp, 3, "%02x", data.buffer[i]);
      tmp += 2;
  }
  printBuffer[data.len] = 0;

  LOG_I("Send data to xapp with client id %d with data size %d and final size %d", client_fd, data.len, sent_size);
  
  // LOG_I("Data Buffer %s", printBuffer);
  
  // Asume we receive the same report all the tine
  // test_return_msg();
  // test_buffer_msg();
  delete buf;
}

void E2Sim::wait_for_sctp_data()
{
  sctp_buffer_t recv_buf;
  if(sctp_receive_data(client_fd, recv_buf) > 0)
  {
    LOG_I("[SCTP] Received new data of size %d", recv_buf.len);
      e2ap_handle_sctp_data(client_fd, recv_buf, this);
  }
}

void E2Sim::generate_e2apv1_subscription_response_success(E2AP_PDU *e2ap_pdu, long reqActionIdsAccepted[], long reqActionIdsRejected[], int accept_size, int reject_size, long reqRequestorId, long reqInstanceId) {
  encoding::generate_e2apv1_subscription_response_success(e2ap_pdu, reqActionIdsAccepted, reqActionIdsRejected, accept_size, reject_size, reqRequestorId, reqInstanceId);
}

void E2Sim::generate_e2apv1_indication_request_parameterized(E2AP_PDU *e2ap_pdu, long requestorId, long instanceId, long ranFunctionId, long actionId, long seqNum, uint8_t *ind_header_buf, int header_length, uint8_t *ind_message_buf, int message_length) {
  encoding::generate_e2apv1_indication_request_parameterized(e2ap_pdu, requestorId, instanceId, ranFunctionId, actionId, seqNum, ind_header_buf, header_length, ind_message_buf, message_length);

}

int E2Sim::run_loop(int argc, char* argv[]){
  options_t ops = read_input_options(argc, argv);
  LOG_D("After reading input options");
  return run_loop(ops.server_ip,ops.server_port,ops.client_port,ops.gnb_id,ops.plmn_id);
}

int E2Sim::run_loop(std::string server_ip, uint16_t server_port, uint16_t local_port, std::string gnb_id, std::string plmn_id) {
    LOG_U("Start E2 Agent (E2 Simulator)");
    LOG_U("Current Log level is %d", LOG_LEVEL);

    client_fd = sctp_start_client(server_ip.c_str(), server_port, local_port);
    auto *pdu_setup = (E2AP_PDU_t *) calloc(1, sizeof(E2AP_PDU));

    LOG_D("After starting client\n");
    LOG_D("client_fd value is %d\n", client_fd);

    std::vector<encoding::ran_func_info> all_funcs;

    // Loop through RAN function definitions that are registered

    for (std::pair<long, OCTET_STRING_t*> elem : ran_functions_registered) {
        LOG_D("Looping through ran func");
        encoding::ran_func_info next_func{};

        next_func.ranFunctionId = elem.first;
        next_func.ranFunctionDesc = elem.second;
        next_func.ranFunctionRev = (long)2;
        all_funcs.push_back(next_func);
    }

    LOG_D("About to call setup request encode");

    generate_e2apv1_setup_request_parameterized(pdu_setup, all_funcs, (uint8_t *) gnb_id.c_str(), (uint8_t *) plmn_id.c_str());

    LOG_D("After generating e2setup req\n");

    // if (LOG_LEVEL == LOG_LEVEL_DEBUG)
    //     xer_fprint(stderr, &asn_DEF_E2AP_PDU, pdu_setup);

    LOG_D("After XER Encoding\n");

    sctp_buffer_t data_buf;
    memset(data_buf.buffer, 0, MAX_SCTP_BUFFER);
    data_buf.len = 0;

    char *error_buf = (char*)calloc(300, sizeof(char));
    size_t errlen;

    auto err_ret = asn_check_constraints(&asn_DEF_E2AP_PDU, pdu_setup, error_buf, &errlen);
    if (err_ret == -1) {
        LOG_E("E2 Setup request constraints check failed, reason:\n%s", error_buf);
    }

    auto er = asn_encode_to_buffer(nullptr, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2AP_PDU, pdu_setup, data_buf.buffer, MAX_SCTP_BUFFER);

    data_buf.len = er.encoded;

    if(sctp_send_data(client_fd, data_buf) > 0) {
        LOG_I("[SCTP] Sent E2-SETUP-REQUEST");
    } else {
        LOG_E("[SCTP] Unable to send E2-SETUP-REQUEST to peer");
    }

    LOG_D("[SCTP] Waiting for SCTP data");

    // test 
    // test_return_msg();
    // test_buffer_msg();
    // return EXIT_SUCCESS;
    // end test

    try {
        SignalHandler signalHandler;
        while (SignalHandler::isRunning()) //constantly looking for data on SCTP interface
        {
            if (sctp_receive_data(client_fd, data_buf) <= 0)
                break;

            // LOG_I("[SCTP] Received n ew data of size %d", data_buf.len);

            e2ap_handle_sctp_data(client_fd, data_buf, this);
        }
    } catch (SignalException &e) {
        LOG_E("SIGINT raised, possible cause: %s", strsignal(SIGINT));
    }

    return EXIT_SUCCESS;
}

void E2Sim::test_buffer_msg(){
  const char* _e2ap_pdu = "40313131010000000100000102003c000000002c0000000100000004584d000000000002be0b02000100000001ff000e00ffffffffffff0300030000003200ffff00000000000000000000003c000000002c0000000100000004e880000000000002be0b02000100000001ff000e00ffffffffffff0800050000003200ffff000000000000000000000101010101010200ff01010100";

  std::string _e2ap_pduString = std::string(_e2ap_pdu);
  std::cout << "Length of string " << _e2ap_pduString.size() << std::endl;

  char* bytes = converHexToByteLocal(_e2ap_pduString);

  // printf("Get length of string -> %d\n", (int)strlen(bytes));

  // int buffer_size = (int)strlen(bytes);
  int buffer_size = (int)_e2ap_pduString.length()/2;

  // uint8_t *e2ApBuffer = (uint8_t *)calloc(1, (_e2ap_pduString.length()));
  // memcpy(e2ApBuffer, bytes, (_e2ap_pduString.length()/2));

  uint8_t *e2ApBuffer = (uint8_t *)calloc(1, buffer_size);
  memcpy(e2ApBuffer, bytes, buffer_size);

  RICcontrolRequest_IEs_t* singleRequest = (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));
  singleRequest->value.present = RICcontrolRequest_IEs__value_PR_RICcontrolMessage;
  singleRequest->value.choice.RICcontrolMessage.buf = e2ApBuffer;
  singleRequest->value.choice.RICcontrolMessage.size = buffer_size;
  singleRequest->id =23;

  InitiatingMessage_t* initMsg = (InitiatingMessage_t * )calloc(1, sizeof(InitiatingMessage_t));
  initMsg->value.present = InitiatingMessage__value_PR_RICcontrolRequest;
  initMsg->criticality = Criticality_ignore;
  ASN_SEQUENCE_ADD(&(initMsg->value.choice.RICcontrolRequest.protocolIEs.list) , singleRequest);    


  E2AP_PDU_t* pdu = (E2AP_PDU_t * )calloc(1, sizeof(E2AP_PDU_t));
  pdu->present = E2AP_PDU_PR_initiatingMessage;
  pdu->choice.initiatingMessage = initMsg;
  
  get_sm_callback(300)(pdu);

}

void E2Sim::test_return_msg(){
    std::vector<long> ue_id_vec {7}; // {1,2,3,4,5};
    std::vector<long> start_position_vec {4}; // {1,2,3,4,5};
    std::vector<long> optimized_vec {2}; // {2,1,4,3,5};
    // for(int _ind = 0; _ind<(int)size; ++_ind){
    //     ue_id_vec[_ind] = (ue_id[_ind]);
    //     start_position_vec[_ind] = (start_position[_ind]);
    //     optimized_vec[_ind] = (optimized[_ind]);
    // }

    std::set<long> sourceCellIdSet;
    for (long x: start_position_vec){
        sourceCellIdSet.insert(x);
    }

    std::string plmn("111");
    LOG_D("Plmn %s", plmn.c_str());

    AllHandoversListPlmn_t* allHandoversListPlmn = (AllHandoversListPlmn_t *) calloc(1, sizeof(AllHandoversListPlmn_t));

    AllHandoversList_t* allHandoversList = (AllHandoversList_t *) calloc(1, sizeof(AllHandoversList_t));
    allHandoversListPlmn->plmn_id.buf = (uint8_t *) calloc (1, 3);
    allHandoversListPlmn->plmn_id.size = 3;
    memcpy (allHandoversListPlmn->plmn_id.buf, plmn.c_str (), 3);

    allHandoversListPlmn->allHandoversList = allHandoversList;

    for (long sourceCellId: sourceCellIdSet){
        CellHandoverList_t* cellHandovers = (CellHandoverList_t *) calloc(1, sizeof(CellHandoverList_t));
        cellHandovers->sourceCellId = sourceCellId;
        // find items in the starting vec from the set
        std::vector<int> indices = encoding::findItems(start_position_vec, sourceCellId);
        std::list<CellHandoverItem_t*> handoverItems;
        for (int index : indices){
            long _ue_ind = ue_id_vec.at(index);
            long _dst_cell_id = optimized_vec.at(index);
            CellHandoverItem_t* control_message = encoding::create_handover_item(_ue_ind, _dst_cell_id);
            handoverItems.push_back(control_message);
        }
        CellHandoverItemList_t* cellHandoverList = encoding::create_handover_item_list(handoverItems);
        cellHandovers->cellHandoverItemList = cellHandoverList;
        ASN_SEQUENCE_ADD(&allHandoversList->list, cellHandovers);
    }

    E2SM_RC_ControlMessage_t* rcControlMessage = (E2SM_RC_ControlMessage_t *) calloc(1, sizeof(E2SM_RC_ControlMessage_t));
    rcControlMessage->present = E2SM_RC_ControlMessage_PR_handoverMessage_Format;
    // rcControlMessage->choice.handoverMessage_Format = allHandoversList;
    rcControlMessage->choice.handoverMessage_Format = allHandoversListPlmn;

    // uint8_t* buf;
    unsigned char buf[MAX_SCTP_BUFFER];
    memset(buf, 0, MAX_SCTP_BUFFER);
    size_t len = 0;

    auto er = asn_encode_to_buffer(nullptr, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_RC_ControlMessage, rcControlMessage, buf, MAX_SCTP_BUFFER);
    len = er.encoded;
    // int len = aper_encode_to_new_buffer(&asn_DEF_E2SM_RC_ControlMessage, 0, rcControlMessage, (void **)&buf);

    RICcontrolRequest_IEs_t* singleRequest = (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));
    singleRequest->value.present = RICcontrolRequest_IEs__value_PR_RICcontrolMessage;
    singleRequest->value.choice.RICcontrolMessage.buf = buf;
    singleRequest->value.choice.RICcontrolMessage.size = len;


    // RICcontrolRequest_IEs_t *ies_richead = (RICcontrolRequest_IEs_t *)calloc(1, sizeof(RICcontrolRequest_IEs_t));
    // ies_richead->criticality = Criticality_reject;
    // ies_richead->id = ProtocolIE_ID_id_RICcontrolHeader;
    // ies_richead->value.present = RICcontrolRequest_IEs__value_PR_RICcontrolHeader;
    // ies_richead->value.choice.RICcontrolHeader.size = 0;


    // RICcontrolRequest_t * ric_control_request = (RICcontrolRequest_t * )calloc(1, sizeof(RICcontrolRequest_t));
    // ASN_SEQUENCE_ADD(&(ric_control_request->protocolIEs.list), singleRequest);    

    InitiatingMessage_t* initMsg = (InitiatingMessage_t * )calloc(1, sizeof(InitiatingMessage_t));
    initMsg->value.present = InitiatingMessage__value_PR_RICcontrolRequest;
    initMsg->criticality = Criticality_ignore;
    ASN_SEQUENCE_ADD(&(initMsg->value.choice.RICcontrolRequest.protocolIEs.list) , singleRequest);    


    E2AP_PDU_t* pdu = (E2AP_PDU_t * )calloc(1, sizeof(E2AP_PDU_t));
    pdu->present = E2AP_PDU_PR_initiatingMessage;
    pdu->choice.initiatingMessage = initMsg;
    
    // NS_LOG_INFO ();
    // 
    // xer_fprint(stderr, &asn_DEF_E2AP_PDU, pdu);

    xer_fprint(stderr, &asn_DEF_E2SM_RC_ControlMessage, rcControlMessage);

    // reverse the encoding of e2sm control msg

    unsigned char new_buf[len];
    memcpy(new_buf, buf, len);

    LOG_D("Len og buff %ld", len);
    
    // E2SM_RC_ControlMessage_t* rcNewControlMessage = (E2SM_RC_ControlMessage_t *) calloc(1,
    //                                                                          sizeof(E2SM_RC_ControlMessage_t));
    // ASN_STRUCT_RESET(asn_DEF_E2SM_RC_ControlMessage, rcNewControlMessage);
    // asn_dec_rval_t dec_ret = asn_decode(nullptr, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_RC_ControlMessage, (void **) &rcNewControlMessage, new_buf, len);
    // xer_fprint(stderr, &asn_DEF_E2SM_RC_ControlMessage, rcNewControlMessage);
    // if (dec_ret.code != RC_OK) {
    //     std::cout << "Error happening" << std::endl;
    // } else {
    //     xer_fprint(stderr, &asn_DEF_E2SM_RC_ControlMessage, rcNewControlMessage);
    // }

    get_sm_callback(300)(pdu);
};