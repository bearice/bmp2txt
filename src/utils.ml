let debug_hex_dump buf = Hex.hexdump (Hex.of_bytes buf) ;;
let bytes_remaining buf off = Bytes.sub buf off ((Bytes.length buf)-off) ;;
let buf_to_string buf = 
  let out = Buffer.create ((Bytes.length buf) * 3) in
  let ( <= ) buf s = Buffer.add_string buf s in
  let len = Bytes.length buf in
  for i = 0 to len-1 do
    out <= Printf.sprintf (if i < (len-1) then "%02x:" else "%02x") (Bytes.get_uint8 buf i)
  done;
  Buffer.contents out
;;
let show_flags d = 
  let rec aux acc d =
    if d = 0 then acc else
      aux (string_of_int (d land 1) :: acc) (d lsr 1)
  in
  let ret = String.concat "" ("00000000"::(aux [] d)) in
  String.sub ret ((String.length ret)-8) 8 
;;

let read_list map_fn parser_fn buf = 
  if Bytes.length buf = 0 then [] else
    let rec read_list_rec hd offset =
      let (elem,offset) = parser_fn buf offset in
      let hd = elem :: hd in 
      if offset < Bytes.length buf then
        read_list_rec hd offset
      else
        hd
    in
    List.rev_map map_fn @@ read_list_rec [] 0
;;
