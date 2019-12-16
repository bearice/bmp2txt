open Utils;;
open Bgp;;

type bmp_peer_type = PEER_TYPE_GLOBAL | PEER_TYPE_RD | PEER_TYPE_LOCAL | PEER_TYPE_UNKNOWN of int [@@deriving show { with_path = false }] ;;
let read_bmp_peer_type t = match t with
  | 0 -> PEER_TYPE_GLOBAL
  | 1 -> PEER_TYPE_RD
  | 2 -> PEER_TYPE_LOCAL
  | x -> PEER_TYPE_UNKNOWN x
;;
let bmp_peer_type_to_yojson t = `String (show_bmp_peer_type t)

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
let bmp_peer_header_to_yojson x = `Assoc [
    ("type",bmp_peer_type_to_yojson x.typ);
    ("flag",`Int x.flg);
    ("pd",`String (buf_to_string x.pd));
    ("addr",ip_to_yojson x.addr);
    ("peer_as",`Intlit (Int32.to_string x.peer_as));
    ("peer_id",ipv4_to_yojson x.peer_id);
    ("ts",`Intlit (Int32.to_string x.ts));
    ("ts_us",`Intlit (Int32.to_string x.ts_us));
  ];;
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


type bmp_info_raw = { typ: int; len: int; msg: string} [@@deriving to_yojson, show { with_path = false }] ;;
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
[@@deriving to_yojson, show { with_path = false }] ;;
let read_bmp_info raw = match raw.typ with
  | 0 -> String raw.msg
  | 1 -> SysDescr raw.msg
  | 2 -> SysName raw.msg
  | _ -> Unknown raw
;;

let read_bmp_info_list = read_list read_bmp_info read_bmp_info_raw ;;

type bmp_msg_init = bmp_info list [@@deriving to_yojson, show { with_path = false }] ;;
let read_bmp_msg_init = read_bmp_info_list ;;

type bmp_msg_term_type = 
    BMP_MSG_TERM_STRING
  | BMP_MSG_TERM_REASON
  | BMP_MSG_TERM_UNKNOWN of int
[@@deriving to_yojson, show { with_path = false }] ;;
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
[@@deriving to_yojson, show { with_path = false }] ;;
let read_bmp_msg_term_reason t =  match t with
  | 0 -> BMP_MSG_TERM_REASON_CEASED
  | 1 -> BMP_MSG_TERM_REASON_UNSPECIFIED
  | 2 -> BMP_MSG_TERM_REASON_OUT_OF_RESOURCE
  | 3 -> BMP_MSG_TERM_REASON_ADMIN_SHUTDOWN
  | x -> BMP_MSG_TERM_REASON_UNKNOWN x
;;

type bmp_msg_term = { typ: bmp_msg_term_type; len: int; msg: string option; reason: bmp_msg_term_reason option} [@@deriving to_yojson, show { with_path = false }] ;;
let read_bmp_msg_term buf = 
  let typ = read_bmp_msg_term_type (Bytes.get_uint16_be buf 0) in
  let len = Bytes.get_uint16_be buf 2 in
  let msg = if typ!=BMP_MSG_TERM_REASON then Some (Bytes.sub_string buf 4 len) else None in
  let reason = if typ=BMP_MSG_TERM_REASON then Some (read_bmp_msg_term_reason (Bytes.get_uint16_be buf 4)) else None in
  {typ;len;msg;reason}
;;

type bmp_msg_stat_entry_raw = {t:int;l:int;v:bytes} [@@deriving to_yojson, show { with_path = false }] ;;
let read_bmp_msg_stat_entry_raw buf offset = 
  let t = Bytes.get_uint16_be buf offset in
  let l = Bytes.get_uint16_be buf (offset+2) in
  let v = Bytes.sub buf (offset+4) l in
  let tlv = {t;l;v} in
  let offset = offset+4+l in
  (tlv,offset)
;;
type bmp_msg_stat_entry = 
  | STATS_PREFIX_REJ of int32
  | STATS_DUP_PREFIX of int32
  | STATS_DUP_WITHDRAW of int32
  | STATS_INVALID_CLUSTER_LIST of int32
  | STATS_INVALID_AS_PATH_LOOP of int32
  | STATS_INVALID_ORIGINATOR_ID of int32
  | STATS_INVALID_AS_CONFED_LOOP of int32
  | STATS_NUM_ROUTES_ADJ_RIB_IN of int64
  | STATS_NUM_ROUTES_LOC_RIB of int64
  | STATS_NUM_ROUTES_ADJ_RIB_IN_PER_AFI of bgp_afi*bgp_safi*int64
  | STATS_NUM_ROUTES_LOC_RIB_PER_AFI of bgp_afi*bgp_safi*int64
  | STATS_UPDATES_AS_WITHDRAW of int32
  | STATS_UPDATES_AS_WITHDRAW_PREFIX of int32
  | STATS_DUP_UPDATE of int32
  | STATS_UNKNOWN of bmp_msg_stat_entry_raw
[@@deriving to_yojson, show { with_path = false }] ;;
let read_bmp_msg_stat_entry raw = match raw.t with 
  | 0 -> STATS_PREFIX_REJ (Bytes.get_int32_be raw.v 0)
  | 1 -> STATS_DUP_PREFIX (Bytes.get_int32_be raw.v 0)
  | 2 -> STATS_DUP_WITHDRAW (Bytes.get_int32_be raw.v 0)
  | 3 -> STATS_INVALID_CLUSTER_LIST (Bytes.get_int32_be raw.v 0)
  | 4 -> STATS_INVALID_AS_PATH_LOOP (Bytes.get_int32_be raw.v 0)
  | 5 -> STATS_INVALID_ORIGINATOR_ID (Bytes.get_int32_be raw.v 0)
  | 6 -> STATS_INVALID_AS_CONFED_LOOP (Bytes.get_int32_be raw.v 0)
  | 7 -> STATS_NUM_ROUTES_ADJ_RIB_IN (Bytes.get_int64_be raw.v 0)
  | 8 -> STATS_NUM_ROUTES_LOC_RIB (Bytes.get_int64_be raw.v 0)
  | 9 -> STATS_NUM_ROUTES_ADJ_RIB_IN_PER_AFI ((read_bgp_afi @@ Bytes.get_int16_be raw.v 0),(read_bgp_safi @@ Bytes.get_int8 raw.v 2),(Bytes.get_int64_be raw.v 3))
  | 10 -> STATS_NUM_ROUTES_LOC_RIB_PER_AFI ((read_bgp_afi @@ Bytes.get_int16_be raw.v 0),(read_bgp_safi @@ Bytes.get_int8 raw.v 2),(Bytes.get_int64_be raw.v 3))
  | 11 -> STATS_UPDATES_AS_WITHDRAW (Bytes.get_int32_be raw.v 0)
  | 12 -> STATS_UPDATES_AS_WITHDRAW_PREFIX (Bytes.get_int32_be raw.v 0)
  | 13 -> STATS_DUP_UPDATE (Bytes.get_int32_be raw.v 0)
  | _ -> STATS_UNKNOWN raw

type bmp_msg_stat_entry_list = bmp_msg_stat_entry list [@@deriving to_yojson, show { with_path = false }] ;;
let read_bmp_msg_stat_entry_list = read_list read_bmp_msg_stat_entry read_bmp_msg_stat_entry_raw
let bmp_msg_stat_entry_list_to_yojson l = 
  let map_fn x = match bmp_msg_stat_entry_to_yojson x with
    | `List [name;value] -> `Assoc [("type",name);("value",value)] 
    | `List [name;afi;safi;value] -> `Assoc [("type",name);("afi",afi);("safi",safi);("value",value)] 
    | x -> x in
  let lst = List.map map_fn l in 
  `List lst
;;

type bmp_msg_stat = { 
  peer_hdr: bmp_peer_header; 
  count: int32; 
  data: bmp_msg_stat_entry_list
} [@@deriving to_yojson, show { with_path = false }] ;;
let read_bmp_msg_stat buf = 
  let (peer_hdr,buf) = read_bmp_peer_header buf in
  let count = Bytes.get_int32_be buf 0 in
  let buf = bytes_remaining buf 4 in
  let data = read_bmp_msg_stat_entry_list buf in
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

let bmp_msg_peer_up_to_yojson x = `Assoc [
    ("peer_hdr",bmp_peer_header_to_yojson x.peer_hdr);
    ("local_addr",ip_to_yojson x.local_addr);
    ("local_port",`Int x.local_port);
    ("remote_port",`Int x.remote_port);
    ("sent_open_msg",bgp_msg_open_to_yojson x.sent_open_msg);
    ("recv_open_msg",bgp_msg_open_to_yojson x.recv_open_msg);
  ];;

type bmp_msg_peer_down = { peer_hdr: bmp_peer_header; reason: int; data: bytes option} [@@deriving to_yojson,show { with_path = false }] ;;
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

type bmp_msg_route_monitor = {
  peer_hdr: bmp_peer_header; 
  update_msg: bgp_msg_update;
} [@@deriving to_yojson, show { with_path = false }] ;;
let read_bmp_msg_route_monitor buf = 
  let (peer_hdr,buf) = read_bmp_peer_header buf in
  let update_msg = read_bgp_msg_update buf in
  {peer_hdr;update_msg}
;;

type bmp_msg_raw = { ver: int; len: int; typ:int; payload:bytes } [@@deriving to_yojson, show { with_path = false }] ;;
let read_bmp_msg_raw buf = 
  let open Bytes in
  let ver = get_uint8 buf 0 in
  let len = Int32.to_int @@ get_int32_be buf 1 in
  let typ = get_uint8 buf 5 in
  let len = len - 6 in
  let payload = bytes_remaining buf 6 in
  {ver;len;typ;payload}
;;
(* let bmp_msg_init_to_yojson _x = `String "x";;
   let bmp_msg_term_to_yojson _x = `String "x";;
   let bmp_msg_stat_to_yojson _x = `String "x";;
   let bmp_msg_raw_to_yojson _x  = `String "x";; *)
(* let bmp_msg_peer_up_to_yojson _x       = `String "x";;
   let bmp_msg_peer_down_to_yojson _x     = `String "x";;
   let bmp_msg_route_monitor_to_yojson _x = `String "x";; *)

type bmp_msg = 
    Init of bmp_msg_init
  | Term of bmp_msg_term
  | PeerUp of bmp_msg_peer_up
  | PeerDown of bmp_msg_peer_down
  | Stat of bmp_msg_stat
  | RouteMonitor of bmp_msg_route_monitor
  | Unknown of bmp_msg_raw
[@@deriving to_yojson, show { with_path = false }] 
;;

let obj_lst x = match x with `Assoc a -> a | _ -> [] ;;
let add_typ t x = ("type",`String t) :: (obj_lst x)
let bmp_msg_to_yojson msg =
  let kv = match msg with
    | Init x -> add_typ "init" @@ bmp_msg_init_to_yojson x
    | Term x -> add_typ "term" @@ bmp_msg_term_to_yojson x
    | PeerUp x -> add_typ "peer_up" @@ bmp_msg_peer_up_to_yojson x
    | PeerDown x -> add_typ "peer_dn" @@ bmp_msg_peer_down_to_yojson x
    | Stat x -> add_typ "stat" @@ bmp_msg_stat_to_yojson x
    | RouteMonitor x -> add_typ "route_monitor" @@ bmp_msg_route_monitor_to_yojson x
    | Unknown x -> add_typ "unknown" @@ bmp_msg_raw_to_yojson x
  in
  `Assoc kv
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