open Utils;;
open Bgp;;

type bmp_peer_type = PEER_TYPE_GLOBAL | PEER_TYPE_RD | PEER_TYPE_LOCAL | PEER_TYPE_UNKNOWN of int [@@deriving show { with_path = false }] ;;
let read_bmp_peer_type t = match t with
  | 0 -> PEER_TYPE_GLOBAL
  | 1 -> PEER_TYPE_RD
  | 2 -> PEER_TYPE_LOCAL
  | x -> PEER_TYPE_UNKNOWN x
;;

type bmp_peer_header = {
  typ: bmp_peer_type;
  flg: int [@printer fun fmt i-> fprintf fmt "%s" (show_flags i)];
  pd: bytes [@printer fun fmt i-> fprintf fmt "%s" (buf_to_string i)];
  addr: Ipaddr.t;
  peer_as: int32;
  peer_id: Ipaddr.V4.t;
  ts: int32;
  ts_us: int32;
} [@@deriving show { with_path = false }] ;;
let read_bmp_peer_header buf = 
  let typ = read_bmp_peer_type (Bytes.get_uint8 buf 0) in
  let flg = Bytes.get_uint8 buf 1 in
  let pd = Bytes.sub buf 2 8 in
  let addr = Bytes.sub_string buf 10 16 in
  let addr = if flg land 0b1000000 = 0 then
      Ipaddr.V4 (Ipaddr.V4.of_octets_exn ~off:12 addr) 
    else 
      Ipaddr.V6 (Ipaddr.V6.of_octets_exn addr) 
  in
  let peer_as = Bytes.get_int32_be buf 26 in
  let peer_id = Bytes.get_int32_be buf 30 in
  let peer_id = Ipaddr.V4.of_int32 peer_id in
  let ts = Bytes.get_int32_be buf 34 in
  let ts_us = Bytes.get_int32_be buf 38 in
  let rem_len = (Bytes.length buf)-42 in
  let rem = Bytes.sub buf 42 rem_len in
  let ret = {typ;flg;pd;addr;peer_as;peer_id;ts;ts_us} in
  (* print_endline (show_bmp_msg_peer_header ret); *)
  (ret,rem)
;;


type bmp_info_raw = { typ: int; len: int; msg: string} [@@deriving show { with_path = false }] ;;
let read_bmp_info_raw buf offset = 
  let typ = Bytes.get_uint16_be buf offset in
  let len = Bytes.get_uint16_be buf (offset+2) in
  let msg = Bytes.sub_string buf (offset+4) len in
  let tlv = {typ;len;msg} in
  let offset = offset+len+4 in
  (tlv,offset)
;;


type bmp_info = 
    String of string
  | SysDescr of string
  | SysName of string
  | Unknown of bmp_info_raw
[@@deriving show { with_path = false }] ;;
let read_bmp_info raw = match raw.typ with
  | 0 -> String raw.msg
  | 1 -> SysDescr raw.msg
  | 2 -> SysName raw.msg
  | _ -> Unknown raw
;;

let read_bmp_info_list = read_list read_bmp_info read_bmp_info_raw ;;

type bmp_msg_init = bmp_info list [@@deriving show { with_path = false }] ;;
let read_bmp_msg_init = read_bmp_info_list ;;

type bmp_msg_term_type = 
    BMP_MSG_TERM_STRING
  | BMP_MSG_TERM_REASON
  | BMP_MSG_TERM_UNKNOWN of int
[@@deriving show { with_path = false }] ;;
let read_bmp_msg_term_type t = match t with
  | 0 -> BMP_MSG_TERM_STRING
  | 1 -> BMP_MSG_TERM_REASON
  | x -> BMP_MSG_TERM_UNKNOWN x
;;

type bmp_msg_term_reason = 
    BMP_MSG_TERM_REASON_CEASED
  | BMP_MSG_TERM_REASON_UNSPECIFIED
  | BMP_MSG_TERM_REASON_OUT_OF_RESOURCE
  | BMP_MSG_TERM_REASON_ADMIN_SHUTDOWN
  | BMP_MSG_TERM_REASON_UNKNOWN of int
[@@deriving show { with_path = false }] ;;
let read_bmp_msg_term_reason t =  match t with
  | 0 -> BMP_MSG_TERM_REASON_CEASED
  | 1 -> BMP_MSG_TERM_REASON_UNSPECIFIED
  | 2 -> BMP_MSG_TERM_REASON_OUT_OF_RESOURCE
  | 3 -> BMP_MSG_TERM_REASON_ADMIN_SHUTDOWN
  | x -> BMP_MSG_TERM_REASON_UNKNOWN x
;;

type bmp_msg_term = { typ: bmp_msg_term_type; len: int; msg: string option; reason: bmp_msg_term_reason option} [@@deriving show { with_path = false }] ;;
let read_bmp_msg_term buf = 
  let typ = read_bmp_msg_term_type (Bytes.get_uint16_be buf 0) in
  let len = Bytes.get_uint16_be buf 2 in
  let msg = if typ!=BMP_MSG_TERM_REASON then Some (Bytes.sub_string buf 4 len) else None in
  let reason = if typ=BMP_MSG_TERM_REASON then Some (read_bmp_msg_term_reason (Bytes.get_uint16_be buf 4)) else None in
  {typ;len;msg;reason}
;;

type bmp_msg_stat_entry_raw = {t:int;l:int;v:bytes} [@@deriving show { with_path = false }] ;;
let read_bmp_msg_stat_entry_raw buf offset = 
  let t = Bytes.get_uint16_be buf offset in
  let l = Bytes.get_uint16_be buf (offset+2) in
  let v = Bytes.sub buf (offset+4) l in
  let tlv = {t;l;v} in
  let offset = offset+4+l in
  (tlv,offset)
;;
type bmp_msg_stat_entry = 
    STATS_PREFIX_REJ of int32
  | STATS_DUP_PREFIX of int32
  | STATS_DUP_WITHDRAW of int32
  | STATS_INVALID_CLUSTER_LIST of int32
  | STATS_INVALID_AS_PATH_LOOP of int32
  | STATS_INVALID_ORIGINATOR_ID of int32
  | STATS_INVALID_AS_CONFED_LOOP of int32
  | STATS_NUM_ROUTES_ADJ_RIB_IN of int64
  | STATS_NUM_ROUTES_LOC_RIB of int64
  | STATS_NUM_ROUTES_ADJ_RIB_IN_PER_AFI of int*int*int64
  | STATS_NUM_ROUTES_LOC_RIB_PER_AFI of int*int*int64
  | STATS_UPDATES_AS_WITHDRAW of int32
  | STATS_UPDATES_AS_WITHDRAW_PREFIX of int32
  | STATS_DUP_UPDATE of int32
  | STATS_UNKNOWN of bmp_msg_stat_entry_raw
[@@deriving show { with_path = false }] ;;
let read_bmp_msg_stat_entry raw = STATS_UNKNOWN raw

let read_bmp_msg_stat_list = read_list read_bmp_msg_stat_entry read_bmp_msg_stat_entry_raw

type bmp_msg_stat = { peer_hdr: bmp_peer_header; count: int32; data: bmp_msg_stat_entry list} [@@deriving show { with_path = false }] ;;
let read_bmp_msg_stat buf = 
  let (peer_hdr,buf) = read_bmp_peer_header buf in
  let count = Bytes.get_int32_be buf 0 in
  let buf = bytes_remaining buf 4 in
  let data = read_bmp_msg_stat_list buf in
  {peer_hdr;count;data}

type bmp_msg_peer_up = { 
  peer_hdr: bmp_peer_header;
  local_addr: Ipaddr.t;
  local_port: int;
  remote_port: int;
  sent_open_msg: bgp_msg_open;
  recv_open_msg: bgp_msg_open;
  info: bmp_info list;
} [@@deriving show { with_path = false }] ;;
let read_bmp_msg_peer_up buf = 
  let (peer_hdr,buf) = read_bmp_peer_header buf in
  let local_addr = Bytes.sub_string buf 0 16 in
  let local_addr = if peer_hdr.flg land 0b1000000 = 0 then
      Ipaddr.V4 (Ipaddr.V4.of_octets_exn ~off:12 local_addr) 
    else 
      Ipaddr.V6 (Ipaddr.V6.of_octets_exn local_addr) 
  in 
  let local_port = Bytes.get_uint16_be buf 16 in
  let remote_port = Bytes.get_uint16_be buf 18 in
  let buf = bytes_remaining buf 20 in
  let (sent_open_msg,buf) = read_bgp_msg_open buf in
  let (recv_open_msg,buf) = read_bgp_msg_open buf in
  (* let _ = debug_hex_dump buf in *)
  let info = if Bytes.length buf > 0 then read_bmp_info_list buf else [] in
  {peer_hdr;local_addr;local_port;remote_port;sent_open_msg;recv_open_msg;info}
;;

type bmp_msg_peer_down = { peer_hdr: bmp_peer_header; reason: int; data: bytes option} [@@deriving show { with_path = false }] ;;
let read_bmp_msg_peer_down buf = 
  let (peer_hdr,buf) = read_bmp_peer_header buf in
  let reason = Bytes.get_uint8 buf 0 in
  let data_len = (Bytes.length buf) - 1 in
  let data = match reason with 
    | 1 -> Some (Bytes.sub buf 1 data_len)
    | 2 -> Some (Bytes.sub buf 1 data_len)
    | 3 -> Some (Bytes.sub buf 1 data_len)
    | _ -> None
  in
  {peer_hdr;reason;data}
;;

type bmp_msg_route_monitor = {peer_hdr: bmp_peer_header; update_msg: bgp_msg_update} [@@deriving show { with_path = false }] ;;
let read_bmp_msg_route_monitor buf = 
  let (peer_hdr,buf) = read_bmp_peer_header buf in
  let update_msg = read_bgp_msg_update buf in
  {peer_hdr;update_msg}
;;

type bmp_msg_raw = { ver: int; len: int; typ:int; payload:bytes } [@@deriving show { with_path = false }] ;;
let read_bmp_msg_raw buf = 
  let open Bytes in
  let ver = get_uint8 buf 0 in
  let len = Int32.to_int @@ get_int32_be buf 1 in
  let typ = get_uint8 buf 5 in
  let len = len - 6 in
  let payload = bytes_remaining buf 6 in
  {ver;len;typ;payload}
;;

type bmp_msg = 
    Init of bmp_msg_init 
  | Term of bmp_msg_term 
  | PeerUp of bmp_msg_peer_up 
  | PeerDown of bmp_msg_peer_down 
  | Stat of bmp_msg_stat 
  | RouteMonitor of bmp_msg_route_monitor 
  | Unknown of bmp_msg_raw
[@@deriving show { with_path = false }] ;;

let read_bmp_msg raw = match raw.typ with
  | 0 -> RouteMonitor(read_bmp_msg_route_monitor raw.payload)
  | 1 -> Stat(read_bmp_msg_stat raw.payload)
  | 2 -> PeerDown(read_bmp_msg_peer_down raw.payload)
  | 3 -> PeerUp(read_bmp_msg_peer_up raw.payload)
  | 4 -> Init(read_bmp_msg_init raw.payload)
  | 5 -> Term(read_bmp_msg_term raw.payload)
  | _ -> Unknown raw
;;

let input_bmp_msg ic = 
  let buf = Bytes.create 6 in
  really_input ic buf 0 6;
  let raw = read_bmp_msg_raw buf in
  let payload = Bytes.create raw.len in
  really_input ic payload 0 raw.len;
  read_bmp_msg {raw with payload}
let bmp_msg_of_bytes buf = read_bmp_msg @@ read_bmp_msg_raw buf 