open Utils;;
type bgp_msg_type = BGP_MSG_OPEN | BGP_MSG_UPDATE | BGP_MSG_NOTIFICATION | BGP_MSG_KEEPALIVE | BGP_MSG_UNKNOWN of int [@@deriving show { with_path = false }];;
let read_bgp_msg_type t = match t with
  | 1 -> BGP_MSG_OPEN
  | 2 -> BGP_MSG_UPDATE
  | 3 -> BGP_MSG_NOTIFICATION
  | 4 -> BGP_MSG_KEEPALIVE
  | x -> BGP_MSG_UNKNOWN x
;;

type bgp_msg_header = {
  marker: bytes [@printer fun fmt i-> fprintf fmt "%s" (buf_to_string i)];
  len: int;
  typ: bgp_msg_type;
} [@@deriving show { with_path = false }] ;;
let read_bgp_msg_header buf = 
  let marker = Bytes.sub buf 0 16 in
  let len = Bytes.get_uint16_be buf 16 in
  let typ = read_bgp_msg_type (Bytes.get_uint8 buf 18) in
  {marker;len;typ}
;;

type bgp_afi = IP | IPv6 | L2VPN | Unknown of int [@@deriving show { with_path = false }];;
let read_bgp_afi x = match x with 1 -> IP | 2 -> IPv6 | 25 -> L2VPN | x -> Unknown x ;;
type bgp_safi = Unicast | Multicast | MLPSLable | VPLS | EVPN | MPLSVPN | Unknown of int [@@deriving show { with_path = false }];;
let read_bgp_safi x = match x with 1 -> Unicast | 2 -> Multicast | 4 -> MLPSLable | 65 -> VPLS | 70 -> EVPN | 128 -> MPLSVPN | x -> Unknown x ;;

type bgp_capability_raw = {
  typ: int;
  len: int;
  msg: bytes [@printer fun fmt i-> fprintf fmt "%s" (buf_to_string i)];
} [@@deriving show { with_path = false }] ;;
let read_bgp_capability_raw buf = 
  let typ = Bytes.get_uint8 buf 0 in 
  let len = Bytes.get_uint8 buf 1 in
  let msg = Bytes.sub buf 2 len in
  let tlv = {typ;len;msg} in
  tlv
;;

type bgp_capability = 
    Multiprotocol of bgp_afi*bgp_safi
  | RouteRefresh of bgp_capability_raw
  | GracefulRestart of bgp_capability_raw
  | AS4 of int32
  | LLGR of bgp_capability_raw
  | Unknown of bgp_capability_raw 
[@@deriving show { with_path = false }] ;;
let read_bgp_capability raw = match raw.typ with
    1  ->
    let afi = Bytes.get_int16_be raw.msg 0 and safi = Bytes.get_uint8 raw.msg 3 in
    Multiprotocol (read_bgp_afi afi,read_bgp_safi safi)
  | 2  -> RouteRefresh raw
  | 64 -> GracefulRestart raw
  | 65 -> AS4 (Bytes.get_int32_be raw.msg 0)
  | 71 -> LLGR raw
  | _  -> Unknown raw
;;

type bgp_msg_open_params_raw = {
  typ: int;
  len: int;
  msg: bytes [@printer fun fmt i-> fprintf fmt "%s" (buf_to_string i)];
} [@@deriving show { with_path = false }] ;;
let read_bgp_msg_open_params_raw buf offset = 
  let typ = Bytes.get_uint8 buf (offset+0) in 
  let len = Bytes.get_uint8 buf (offset+1) in
  let msg = Bytes.sub buf (offset+2) len in
  let offset = offset+2+len in
  let tlv = {typ;len;msg} in
  (tlv,offset)
;;

type bgp_msg_open_params = Capability of bgp_capability | Unknown of bgp_msg_open_params_raw [@@deriving show { with_path = false }] ;;
let read_bgp_msg_open_params raw = match raw.typ with
    2 -> Capability (read_bgp_capability (read_bgp_capability_raw raw.msg))
  | _ -> Unknown raw
;;

let read_bgp_msg_open_params_list = read_list read_bgp_msg_open_params read_bgp_msg_open_params_raw

type bgp_msg_open = { 
  bgp_hdr: bgp_msg_header;
  ver: int;
  my_as: int;   
  hold_time : int;
  bgp_identifier : Ipaddr.V4.t;
  opt_len: int;
  opts: bgp_msg_open_params list;
} [@@deriving show { with_path = false }] ;; 
let read_bgp_msg_open buf = 
  let bgp_hdr = read_bgp_msg_header buf in
  let buf = bytes_remaining buf 19 in
  (* let _ = debug_hex_dump buf in *)
  let ver = Bytes.get_uint8 buf 0 in
  let my_as = Bytes.get_uint16_be buf 1 in
  let hold_time = Bytes.get_uint16_be buf 3 in
  let bgp_identifier = Ipaddr.V4.of_int32 (Bytes.get_int32_be buf 5) in
  let opt_len = Bytes.get_uint8 buf 9 in
  let opt_buf = Bytes.sub buf 10 opt_len in
  let opts = read_bgp_msg_open_params_list opt_buf in
  let offset = 10+opt_len in
  let buf = Bytes.sub buf offset ((Bytes.length buf)-offset) in
  let ret = {bgp_hdr;ver;my_as;hold_time;bgp_identifier;opt_len;opts} in
  (* print_endline (show_bgp_msg_open ret); *)
  (ret,buf)
;;

type bgp_path_attr_raw = {
  flg:int [@printer fun fmt i-> fprintf fmt "%s" (show_flags i)];
  typ:int;
  len:int;
  value:bytes [@printer fun fmt i-> fprintf fmt "%s" (buf_to_string i)];
} [@@deriving show { with_path = false }] ;;
let read_bgp_path_attr_raw buf offset = 
  let flg = Bytes.get_uint8 buf (offset+0) in
  let typ = Bytes.get_uint8 buf (offset+1) in
  if flg land 0b00010000 > 0 then
    let len = Bytes.get_uint16_be buf (offset+2) in
    let value = Bytes.sub buf (offset+4) len in
    ({flg;typ;len;value},offset+4+len)
  else
    let len = Bytes.get_uint8 buf (offset+2) in
    let value = Bytes.sub buf (offset+3) len in
    ({flg;typ;len;value},offset+3+len)
;;

type bgp_origin = IGP | EGP | INCOMPLETE | UNKNOWN of int [@@deriving show { with_path = false }];;
let read_bgp_origin buf = match Bytes.get_int8 buf 0 with
    0 -> IGP
  | 1 -> EGP
  | 2 -> INCOMPLETE
  | x -> UNKNOWN x
;;

type bgp_as_path_elem = AS_SET of int32 list | AS_SEQ of int32 list | UNKNOWN of int [@@deriving show { with_path = false }];;
let read_bgp_as_path_elem ?(as4=true) buf offset = 
  let t = Bytes.get_uint8 buf (offset+0) in
  let l = Bytes.get_uint8 buf (offset+1) in
  let lst = Array.make l 0l in
  (* debug_hex_dump buf; *)
  for i = 0 to l-1 do
    let a = if as4 then
        Bytes.get_int32_be buf ((offset+2)+(i*4))
      else
        Int32.of_int (Bytes.get_uint16_be buf ((offset+2)+(i*2)))
    in
    Array.set lst i a;
  done;
  let lst = Array.to_list lst in
  let ret = match t with 1 -> AS_SET lst | 2 -> AS_SEQ lst | x -> UNKNOWN x in
  let offset = offset+2+(l*if as4 then 4 else 2) in
  (ret,offset)
;;
let read_bgp_as_path_list ?(as4=true) = read_list (fun x->x) (read_bgp_as_path_elem ~as4) ;;

type bgp_label_list = int list [@@deriving show { with_path = false }];;
let read_bgp_label_list buf = 
  let rec read_label hd offset =
    let x = Bytes.sub buf offset 3 in
    let x = Bytes.extend x 1 0 in
    let x = Bytes.get_int32_be x 0 in
    let x = Int32.to_int x in
    let offset = offset+3 in
    let label = x lsr 4 and eol = 1=(x land 1) in
    if eol then
      let ret = List.rev (label::hd) and rem = bytes_remaining buf offset in
      (ret,rem)
    else
      read_label (label::hd) offset
  in
  read_label [] 0

type bgp_nlri = {
  afi: bgp_afi;
  safi: bgp_safi;
  len:int;
  pfx:bytes;
};;
let pp_bgp_nlri fmt e = match (e.afi,e.safi) with
    (IP,MPLSVPN) -> 
    let (labels,buf) = read_bgp_label_list e.pfx in
    let rd = Bytes.sub buf 0 8 in
    let buf = bytes_remaining buf 8 in
    let plen = e.len-(8*(8+(3*(List.length labels)))) in
    let l = Bytes.length buf in
    let padlen = 4-l in
    let buf = Bytes.extend buf 0 padlen in
    let ip4 = Ipaddr.V4.of_int32 (Bytes.get_int32_be buf 0) in
    Format.fprintf fmt "L=%s RD=%s P=%s/%d" (show_bgp_label_list labels) (buf_to_string rd) (Ipaddr.V4.to_string ip4) plen 
  | (IP,Unicast) -> 
    let l = Bytes.length e.pfx in
    let padlen = 4-l in
    let buf = Bytes.extend e.pfx 0 padlen in
    let ip4 = Ipaddr.V4.of_octets_exn (Bytes.to_string buf) in
    Format.fprintf fmt "%s/%d" (Ipaddr.V4.to_string ip4) e.len 
  | (IPv6,Unicast) ->
    let l = Bytes.length e.pfx in
    let padlen = 16-l in
    let buf = Bytes.extend e.pfx 0 padlen in
    let ip4 = Ipaddr.V6.of_octets_exn (Bytes.to_string buf) in
    Format.fprintf fmt "%s/%d" (Ipaddr.V6.to_string ip4) e.len 
  | _ -> Format.fprintf fmt "%s/%d" (buf_to_string e.pfx) e.len 
;;

let read_bgp_nlri ?(afi=IP) ?(safi=Unicast) buf offset = 
  let len = Bytes.get_uint8 buf (offset+0) in
  let blen = if len = 0 then 0 else ((len-1)/8)+1 in
  (* let _ = Printf.printf "len=%d blen=%d\b" len blen in *)
  let pfx = Bytes.sub buf (offset+1) blen in 
  let offset = offset+1+blen in
  let nlri = {afi;safi;len;pfx} in
  (nlri,offset)
;;
let read_bgp_nlri_list ?(afi=IP) ?(safi=Unicast) = read_list (fun x->x) (read_bgp_nlri ~afi ~safi)

type bgp_mp_next_hop = VPN of bytes*Ipaddr.t | Unknown of bytes
type bgp_mp_reach_nlri =  {
  afi: bgp_afi;
  safi: bgp_safi;
  next_hop: bytes;
  nlri: bgp_nlri list;
} [@@deriving show { with_path = false }] ;;

let read_bgp_mp_reach_nlri buf = 
  let afi = Bytes.get_int16_be buf 0 and safi = Bytes.get_uint8 buf 2 in
  let afi = read_bgp_afi afi and safi = read_bgp_safi safi in
  let nh_len = Bytes.get_uint8 buf 3 in
  let next_hop = Bytes.sub buf 4 nh_len in
  let nlri = bytes_remaining buf (nh_len+4+1) in (*+1 to skip the reversed byte*)
  let nlri = read_bgp_nlri_list ~afi ~safi nlri in
  {afi;safi;next_hop;nlri}
;;

type bgp_mp_unreach_nlri =  {
  afi: bgp_afi;
  safi: bgp_safi;
  nlri: bgp_nlri list;
} [@@deriving show { with_path = false }] ;;

let read_bgp_mp_unreach_nlri buf = 
  let afi = Bytes.get_int16_be buf 0 and safi = Bytes.get_uint8 buf 2 in
  let afi = read_bgp_afi afi and safi = read_bgp_safi safi in
  let nlri = bytes_remaining buf 3 in
  let nlri = read_bgp_nlri_list ~afi ~safi nlri in
  {afi;safi;nlri}
;;

type bgp_path_attr =
    ORIGIN of bgp_origin
  | AS_PATH of bgp_as_path_elem list
  | NEXT_HOP of Ipaddr.V4.t
  | MULTI_EXIT_DISC of int32
  | LOCAL_PREF of int32
  | ATOMIC_AGGREGATE 
  | AGGREGATOR 
  | COMMUNITIES
  | ORIGINATOR_ID
  | CLUSTER_LIST
  | MP_REACH_NLRI of bgp_mp_reach_nlri
  | MP_UNREACH_NLRI of bgp_mp_unreach_nlri
  | EXT_COMMUNITIES of bytes
  | UNKNOWN of bgp_path_attr_raw [@@deriving show { with_path = false }] ;;
let read_bgp_path_attr ?(as4=true) raw = match raw.typ with
    1 -> ORIGIN (read_bgp_origin raw.value)
  | 2 -> AS_PATH (read_bgp_as_path_list ~as4 raw.value)
  | 3 -> NEXT_HOP (Ipaddr.V4.of_octets_exn (Bytes.to_string raw.value))
  | 4 -> MULTI_EXIT_DISC (Bytes.get_int32_be raw.value 0)
  | 5 -> LOCAL_PREF (Bytes.get_int32_be raw.value 0)
  | 6 -> ATOMIC_AGGREGATE
  | 7 -> AGGREGATOR
  | 8 -> COMMUNITIES
  | 9 -> ORIGINATOR_ID
  | 10 -> CLUSTER_LIST
  | 14 -> MP_REACH_NLRI (read_bgp_mp_reach_nlri raw.value)
  | 15 -> MP_UNREACH_NLRI (read_bgp_mp_unreach_nlri raw.value)
  | 16 -> EXT_COMMUNITIES raw.value
  | _ -> UNKNOWN raw
;;

let read_bgp_path_attr_list ?(as4=true) = read_list (read_bgp_path_attr ~as4) read_bgp_path_attr_raw

type bgp_msg_update = {
  hdr: bgp_msg_header;
  withdraw_len: int;
  withdraw: bgp_nlri list;
  attr_len: int;
  attr: bgp_path_attr list;
  nlri: bgp_nlri list;
} [@@deriving show { with_path = false }] ;;
let read_bgp_msg_update ?(as4=true) ?(_ip4=true) buf = 
  let hdr = read_bgp_msg_header buf in
  let buf = bytes_remaining buf 19 in
  (* let _ = debug_hex_dump buf in *)
  let withdraw_len = Bytes.get_uint16_be buf 0 in
  let withdraw = Bytes.sub buf 2 withdraw_len in
  let withdraw = read_bgp_nlri_list withdraw in
  let buf = bytes_remaining buf (withdraw_len+2) in
  let attr_len = Bytes.get_uint16_be buf 0 in
  let attr = Bytes.sub buf 2 attr_len in
  let attr = read_bgp_path_attr_list ~as4:as4 attr in
  let nlri = bytes_remaining buf (attr_len+2) in
  let nlri = read_bgp_nlri_list nlri in
  {hdr;withdraw_len;withdraw;attr_len;attr;nlri}