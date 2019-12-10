
let debug_hex_dump buf = Hex.hexdump (Hex.of_bytes buf) ;;
let bytes_remaining buf off = Bytes.sub buf off ((Bytes.length buf)-off) ;;

let read_list parser_fn buf = 
  if Bytes.length buf == 0 then [] else
  let rec read_list_rec hd offset =
    let (elem,offset) = parser_fn buf offset in
    let hd = elem :: hd in 
    if offset < Bytes.length buf then
      read_list_rec hd offset
    else
      List.rev hd
  in
  read_list_rec [] 0
;;

type bgp_msg_type = BGP_MSG_OPEN | BGP_MSG_UPDATE | BGP_MSG_NOTIFICATION | BGP_MSG_KEEPALIVE | BGP_MSG_UNKNOWN of int [@@deriving show];;
let read_bgp_msg_type t = match t with
  | 1 -> BGP_MSG_OPEN
  | 2 -> BGP_MSG_UPDATE
  | 3 -> BGP_MSG_NOTIFICATION
  | 4 -> BGP_MSG_KEEPALIVE
  | x -> BGP_MSG_UNKNOWN x
;;

type bgp_msg_header = {
  marker: bytes;
  len: int;
  typ: bgp_msg_type;
} [@@deriving show] ;;
let read_bgp_msg_header buf = 
  let marker = Bytes.sub buf 0 16 in
  let len = Bytes.get_uint16_be buf 16 in
  let typ = read_bgp_msg_type (Bytes.get_uint8 buf 18) in
  {marker;len;typ}
;;

type bgp_msg_params = {
  typ: int;
  len: int;
  msg: bytes;
} [@@deriving show] ;;
(* TODO: parse open_params *)

type bgp_msg_open = { 
  bgp_hdr: bgp_msg_header;
  ver: int;
  my_as: int;   
  hold_time : int;
  bgp_identifier : int32;
  opt_len: int;
  opts: bgp_msg_params list;
} [@@deriving show] ;;
let read_bgp_msg_open buf = 
  let bgp_hdr = read_bgp_msg_header buf in
  let buf = bytes_remaining buf 19 in
  (* let _ = debug_hex_dump buf in *)
  let ver = Bytes.get_uint8 buf 0 in
  let my_as = Bytes.get_uint16_be buf 1 in
  let hold_time = Bytes.get_uint16_be buf 3 in
  let bgp_identifier = Bytes.get_int32_be buf 5 in
  let opt_len = Bytes.get_uint8 buf 9 in
  let opts = [] in
  let offset = 10+opt_len in
  let buf = Bytes.sub buf offset ((Bytes.length buf)-offset) in
  let ret = {bgp_hdr;ver;my_as;hold_time;bgp_identifier;opt_len;opts} in
  (* print_endline (show_bgp_msg_open ret); *)
  (ret,buf)
;;

type bgp_msg_path_attr_type = ORIGIN | AS_PATH | NEXT_HOP | MULTI_EXIT_DISC | LOCAL_PREF | ATOMIC_AGGREGATE | AGGREGATOR | UNKNOWN of int [@@deriving show] ;;
let read_bgp_msg_path_attr_type t = match t with
    1 -> ORIGIN
  | 2 -> AS_PATH
  | 3 -> NEXT_HOP
  | 4 -> MULTI_EXIT_DISC
  | 5 -> LOCAL_PREF
  | 6 -> ATOMIC_AGGREGATE
  | 7 -> AGGREGATOR
  | x -> UNKNOWN x
;;

type bgp_msg_path_attr = {
  flg:int;
  typ:bgp_msg_path_attr_type;
  len:int;
  value:bytes;
} [@@deriving show] ;;
let read_bgp_msg_path_attr buf offset = 
  let flg = Bytes.get_uint8 buf (offset+0) in
  let typ = Bytes.get_uint8 buf (offset+1) in
  let typ = read_bgp_msg_path_attr_type typ in
  if flg land 0b00010000 > 0 then
    let len = Bytes.get_uint16_be buf (offset+2) in
    let value = Bytes.sub buf (offset+4) len in
    ({flg;typ;len;value},offset+4+len)
  else
    let len = Bytes.get_uint8 buf (offset+2) in
    (* debug_hex_dump (bytes_remaining buf offset); *)
    (* Printf.printf "len=%d\n" len; *)
    let value = Bytes.sub buf (offset+3) len in
    ({flg;typ;len;value},offset+3+len)
;;
let read_bgp_msg_path_attr_list = read_list read_bgp_msg_path_attr

type bgp_msg_nlri = {
  len:int;
  pfx:bytes;
} [@@deriving show] ;;
let read_bgp_msg_nlri buf offset = 
  let len = Bytes.get_uint8 buf (offset+0) in
  let blen = if len = 0 then 0 else ((len-1)/8)+1 in
  (* let _ = Printf.printf "len=%d blen=%d\b" len blen in *)
  let pfx = Bytes.sub buf (offset+1) blen in 
  let offset = offset+1+blen in
  let nlri = {len;pfx} in
  (nlri,offset)
;;
let read_bgp_msg_nlri_list = read_list read_bgp_msg_nlri

type bgp_msg_update = {
  bgp_hdr: bgp_msg_header;
  withdraw_len: int;
  withdraw: bgp_msg_nlri list;
  attr_len: int;
  attr: bgp_msg_path_attr list;
  nlri: bgp_msg_nlri list;
} [@@deriving show] ;;
let read_bgp_msg_update buf = 
  let bgp_hdr = read_bgp_msg_header buf in
  let buf = bytes_remaining buf 19 in
  (* let _ = debug_hex_dump buf in *)
  let withdraw_len = Bytes.get_uint16_be buf 0 in
  let withdraw = Bytes.sub buf 2 withdraw_len in
  let withdraw = read_bgp_msg_nlri_list withdraw in
  let buf = bytes_remaining buf (withdraw_len+2) in
  let attr_len = Bytes.get_uint16_be buf 0 in
  let attr = Bytes.sub buf 2 attr_len in
  let attr = read_bgp_msg_path_attr_list attr in
  let nlri = bytes_remaining buf (attr_len+2) in
  let nlri = read_bgp_msg_nlri_list nlri in
  {bgp_hdr;withdraw_len;withdraw;attr_len;attr;nlri}

type bmp_msg_peer_type = BMP_MSG_PEER_TYPE_GLOBAL | BMP_MSG_PEER_TYPE_RD | BMP_MSG_PEER_TYPE_LOCAL | BMP_MSG_PEER_TYPE_UNKNOWN of int [@@deriving show] ;;
let read_bmp_msg_peer_type t = match t with
  | 0 -> BMP_MSG_PEER_TYPE_GLOBAL
  | 1 -> BMP_MSG_PEER_TYPE_RD
  | 2 -> BMP_MSG_PEER_TYPE_LOCAL
  | x -> BMP_MSG_PEER_TYPE_UNKNOWN x
;;

type bmp_msg_peer_header = {
  typ: bmp_msg_peer_type;
  flg: int;
  pd: bytes;
  addr: bytes;
  peer_as: int32;
  peer_id: int32;
  ts: int32;
  ts_us: int32;
} [@@deriving show] ;;
let read_bmp_msg_peer_header buf = 
    let typ = read_bmp_msg_peer_type (Bytes.get_uint8 buf 0) in
    let flg = Bytes.get_uint8 buf 1 in
    let pd = Bytes.sub buf 2 8 in
    let addr = Bytes.sub buf 10 16 in
    let peer_as = Bytes.get_int32_be buf 26 in
    let peer_id = Bytes.get_int32_be buf 30 in
    let ts = Bytes.get_int32_be buf 34 in
    let ts_us = Bytes.get_int32_be buf 38 in
    let rem_len = (Bytes.length buf)-42 in
    let rem = Bytes.sub buf 42 rem_len in
    let ret = {typ;flg;pd;addr;peer_as;peer_id;ts;ts_us} in
    (* print_endline (show_bmp_msg_peer_header ret); *)
    (ret,rem)
;;



type bmp_msg_info_type = 
    BMP_MSG_INFO_STRING
  | BMP_MSG_INFO_SYS_DESCR
  | BMP_MSG_INFO_SYS_NAME
  | BMP_MSG_INFO_UNKNOWN of int
[@@deriving show] ;;
let read_bmp_msg_info_type t = match t with
  | 0 -> BMP_MSG_INFO_STRING
  | 1 -> BMP_MSG_INFO_SYS_DESCR
  | 2 -> BMP_MSG_INFO_SYS_NAME
  | x -> BMP_MSG_INFO_UNKNOWN x
;;

type bmp_msg_info = { typ: bmp_msg_info_type; len: int; msg: string} [@@deriving show] ;;
let read_bmp_msg_info buf offset = 
    let typ = read_bmp_msg_info_type (Bytes.get_uint16_be buf offset) in
    let len = Bytes.get_uint16_be buf (offset+2) in
    let msg = Bytes.sub_string buf (offset+4) len in
    let tlv = {typ;len;msg} in
    let offset = offset+len+4 in
    (tlv,offset)
;;
let read_bmp_msg_info_list = read_list read_bmp_msg_info
;;

type bmp_msg_init = { tlvs: bmp_msg_info list} [@@deriving show] ;;
let read_bmp_msg_init buf = {tlvs=read_bmp_msg_info_list buf} ;;

type bmp_msg_term_type = 
    BMP_MSG_TERM_STRING
  | BMP_MSG_TERM_REASON
  | BMP_MSG_TERM_UNKNOWN of int
[@@deriving show] ;;
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
[@@deriving show] ;;
let read_bmp_msg_term_reason t =  match t with
    | 0 -> BMP_MSG_TERM_REASON_CEASED
    | 1 -> BMP_MSG_TERM_REASON_UNSPECIFIED
    | 2 -> BMP_MSG_TERM_REASON_OUT_OF_RESOURCE
    | 3 -> BMP_MSG_TERM_REASON_ADMIN_SHUTDOWN
    | x -> BMP_MSG_TERM_REASON_UNKNOWN x
;;

type bmp_msg_term = { typ: bmp_msg_term_type; len: int; msg: string option; reason: bmp_msg_term_reason option} [@@deriving show] ;;
let read_bmp_msg_term buf = 
  let typ = read_bmp_msg_term_type (Bytes.get_uint16_be buf 0) in
  let len = Bytes.get_uint16_be buf 2 in
  let msg = if typ!=BMP_MSG_TERM_REASON then Some (Bytes.sub_string buf 4 len) else None in
  let reason = if typ==BMP_MSG_TERM_REASON then Some (read_bmp_msg_term_reason (Bytes.get_uint16_be buf 4)) else None in
  {typ;len;msg;reason}
;;

type bmp_msg_stat_entry = {t:int;l:int;v:bytes}
    (* STATS_PREFIX_REJ of int32
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
  | BMP_MSG_STAT_UNKNOWN of int * bytes *)
[@@deriving show] ;;
let read_bmp_msg_stat_entry buf offset = 
  let t = Bytes.get_uint16_be buf offset in
  let l = Bytes.get_uint16_be buf (offset+2) in
  let v = Bytes.sub buf (offset+4) l in
  let tlv = {t;l;v} in
  let offset = offset+4+l in
  (tlv,offset)
;;

let read_bmp_msg_stat_list = read_list read_bmp_msg_stat_entry

type bmp_msg_stat = { peer_hdr: bmp_msg_peer_header; count: int32; data: bmp_msg_stat_entry list} [@@deriving show] ;;
let read_bmp_msg_stat buf = 
  let (peer_hdr,buf) = read_bmp_msg_peer_header buf in
  let count = Bytes.get_int32_be buf 0 in
  let buf = bytes_remaining buf 4 in
  let data = read_bmp_msg_stat_list buf in
  {peer_hdr;count;data}

type bmp_msg_peer_up = { 
  peer_hdr: bmp_msg_peer_header;
  local_addr: bytes;
  local_port: int;
  remote_port: int;
  sent_open_msg: bgp_msg_open;
  recv_open_msg: bgp_msg_open;
  info: bmp_msg_info list;
} [@@deriving show] ;;
let read_bmp_msg_peer_up buf = 
  let (peer_hdr,buf) = read_bmp_msg_peer_header buf in
  let local_addr = Bytes.sub buf 0 16 in
  let local_port = Bytes.get_uint16_be buf 16 in
  let remote_port = Bytes.get_uint16_be buf 18 in
  let buf = bytes_remaining buf 20 in
  let (sent_open_msg,buf) = read_bgp_msg_open buf in
  let (recv_open_msg,buf) = read_bgp_msg_open buf in
  (* let _ = debug_hex_dump buf in *)
  let info = if Bytes.length buf > 0 then read_bmp_msg_info_list buf else [] in
  {peer_hdr;local_addr;local_port;remote_port;sent_open_msg;recv_open_msg;info}
;;

type bmp_msg_peer_down = { peer_hdr: bmp_msg_peer_header; reason: int; data: bytes option} [@@deriving show] ;;
let read_bmp_msg_peer_down buf = 
  let (peer_hdr,buf) = read_bmp_msg_peer_header buf in
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

type bmp_msg_route_monitor = {peer_hdr: bmp_msg_peer_header; update_msg: bgp_msg_update} [@@deriving show] ;;
let read_bmp_msg_route_monitor buf = 
  let (peer_hdr,buf) = read_bmp_msg_peer_header buf in
  let update_msg = read_bgp_msg_update buf in
  {peer_hdr;update_msg}
;;

type bmp_msg_type = 
    BMP_MSG_ROUTE_MONITOR
  | BMP_MSG_STAT 
  | BMP_MSG_PEER_UP 
  | BMP_MSG_PEER_DOWN 
  | BMP_MSG_INIT
  | BMP_MSG_TERM
  | BMP_MSG_ROUTE_MIRROR
  | BMP_MSG_UNKNOWN of int
[@@deriving show] ;;
let read_bmp_msg_type t = match t with
  | 0 -> BMP_MSG_ROUTE_MONITOR
  | 1 -> BMP_MSG_STAT 
  | 2 -> BMP_MSG_PEER_DOWN 
  | 3 -> BMP_MSG_PEER_UP 
  | 4 -> BMP_MSG_INIT
  | 5 -> BMP_MSG_TERM
  | 6 -> BMP_MSG_ROUTE_MIRROR
  | t -> BMP_MSG_UNKNOWN t
;;

type bmp_msg_payload = 
    BMP_Init of bmp_msg_init 
  | BMP_Term of bmp_msg_term 
  | BMP_PeerUp of bmp_msg_peer_up 
  | BMP_PeerDown of bmp_msg_peer_down 
  | BMP_Stat of bmp_msg_stat 
  | BMP_RouteMonitor of bmp_msg_route_monitor 
  | BMP_Unknown of bytes
[@@deriving show] ;;
let read_bmp_msg_payload t buf = match t with
  | BMP_MSG_INIT -> BMP_Init(read_bmp_msg_init buf)
  | BMP_MSG_TERM -> BMP_Term(read_bmp_msg_term buf)
  | BMP_MSG_PEER_UP -> BMP_PeerUp(read_bmp_msg_peer_up buf)
  | BMP_MSG_PEER_DOWN -> BMP_PeerDown(read_bmp_msg_peer_down buf)
  | BMP_MSG_STAT -> BMP_Stat(read_bmp_msg_stat buf)
  | BMP_MSG_ROUTE_MONITOR -> BMP_RouteMonitor(read_bmp_msg_route_monitor buf)
  | _ -> BMP_Unknown buf
;;

type bmp_msg = { ver: int; len: int; typ:bmp_msg_type; payload: bmp_msg_payload } [@@deriving show] ;;
let read_bmp_msg ic = 
  let ver = input_byte ic in
  let len = input_binary_int ic in
  let typ = read_bmp_msg_type (input_byte ic) in
  let len = len - 6 in
  let buf = Bytes.create len in
  let _ = really_input ic buf 0 len in
  let payload = try 
    read_bmp_msg_payload typ buf
  with e ->
    Printf.printf "v=%d t=%s l=%d\n" ver (show_bmp_msg_type typ) len ;
    debug_hex_dump buf;
    let msg = Printexc.to_string e
    and stack = Printexc.get_backtrace () in
    Printf.printf "there was an error: %s%s\n" msg stack;
    raise e
  in
  {ver;len;typ;payload}
;;

let () = 
  let _ = Printexc.record_backtrace true in
  let f = open_in_bin "bmp.bin" in
  let stream_msg _ = try Some (read_bmp_msg f) with End_of_file -> None in
  let msgs = Stream.from stream_msg in
  (*let print_msg msg = Printf.printf "v=%d t=%d l=%d\n" msg.ver msg.typ msg.len in*)
  let print_msg msg = match msg.typ with BMP_MSG_ROUTE_MONITOR -> () | _ -> print_endline (show_bmp_msg msg) in
  Stream.iter print_msg msgs;
;;
