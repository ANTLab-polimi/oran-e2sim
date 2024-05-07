#ifndef CONTROL_MESSAGE_ENCODER_DECODER_H
#define CONTROL_MESSAGE_ENCODER_DECODER_H


// #include <mdclog/mdclog.h>
#include <vector>

extern "C" {
#include "handover_item.h"
#include "all_handovers.h"
#include "all_handovers_plmn.h"
#include "cell_handovers_list.h" 
#include "handover_list.h"
#include "E2SM-RC-ControlMessage.h"
#include "E2AP-PDU.h"


#include "V2X-Scheduling-All-Users.h" 
}

#define MAX_SCTP_BUFFER_CTRL     10000

// namespace ns3{
namespace encoding {

// #ifdef __cplusplus
// extern "C" {
// #endif


  typedef struct sctp_buffer{
    int length;
    // uint8_t buffer[MAX_SCTP_BUFFER_CTRL];
    uint8_t* buffer;
  } sctp_buffer_t;

  typedef struct dest_sched{
    std::vector<sctp_buffer_t> singleUserAllocations;
    // long v2xNodeId;
    long cReselectionCounter;
    long slResourceReselectionCounter;
    long prevSlResoReselCounter;
    long nrSlHarqId;
    long nSelected;
    long tbTxCounter;
  } dest_sched_t;

  typedef struct e2ap_stcp_buffer{
    int msg_length;
    uint8_t* msg_buffer;
  }e2ap_stcp_buffer_t;

  template<typename T>
  std::vector<int> findItems(std::vector<T> const &v, int target);
  CellHandoverItem_t* create_handover_item(long ueId, long destinationCellId);
  CellHandoverItemList_t* create_handover_item_list(std::list<CellHandoverItem_t*> handoverItems);
  int e2ap_asn1c_encode_cell_handovers(CellHandoverList_t* pdu, unsigned char **buffer);

  int e2ap_asn1c_encode_handover_item(CellHandoverItem_t* pdu, unsigned char **buffer);

  int e2ap_asn1c_encode_all_handovers_item_list(CellHandoverItemList_t* pdu, unsigned char **buffer);

  int e2ap_asn1c_encode_all_handovers(AllHandoversList_t* pdu, unsigned char **buffer);

  int e2ap_asn1c_encode_control_message(E2SM_RC_ControlMessage_t* pdu, unsigned char **buffer);

  std::map<long, std::map<long, long>> decode_handover_control_message(uint8_t* buffer, size_t buffSize);
  
  extern encoding::e2ap_stcp_buffer_t* decode_e2ap_to_xml(uint8_t* buffer, size_t buffSize);

  extern std::map<long, std::map<long, encoding::dest_sched_t>> extract_scheduling_map(V2X_Scheduling_All_Users_t* v2XSchedulingAllUsersList); 

  extern std::map<long, std::map<long, long>> extract_handover_map(AllHandoversList_t* pdu);

  extern struct asn_dec_rval_s e2ap_asn1c_decode_handover_item(CellHandoverItem_t *pdu, enum asn_transfer_syntax syntax, unsigned char *buffer, int len);

  extern sctp_buffer_t* gnerate_e2ap_encode_handover_control_message(uint16_t* ue_id, uint16_t* start_position, uint16_t* optimized, size_t size);


// #ifdef __cplusplus
// }
// #endif

}
// }

#endif