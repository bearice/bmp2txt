open Bmp;;
type bmp_metadata = {from: Unix.sockaddr; seq: int} ;;

let show_sockaddr from = match from with 
    Unix.ADDR_INET (addr,port) -> String.concat ":" [(Unix.string_of_inet_addr addr); (Int.to_string port)] 
  | Unix.ADDR_UNIX name -> name

let accept_connection (fd,from) =
  Printf.printf "Connected from %s%!\n" @@ show_sockaddr from;
  let ic = Unix.in_channel_of_descr fd in
  let rec stream_msg seq = 
    try 
      let msg = input_bmp_msg ic in
      let meta = {from;seq} in
      Seq.Cons ((meta,msg),(fun ()-> stream_msg (seq+1))) 
    with 
      End_of_file -> 
      print_endline "EOF reached";
      Seq.Nil 
    | e ->
      (* Printf.printf "v=%d t=%s l=%d\n" ver (show_bmp_msg_type typ) len ;
         debug_hex_dump buf; *)
      let msg = Printexc.to_string e
      and stack = Printexc.get_backtrace () in
      Printf.printf "there was an error: %s%s\n" msg stack;
      raise e
  in
  let msgs = fun ()-> stream_msg 0 in

  let print_msg ({from;seq},msg) = 
    print_int seq ;
    print_string " " ;
    print_string @@ show_sockaddr from ;
    print_string " " ;
    print_endline (show_bmp_msg msg) ;
  in

  let filter_msg (_,_msg) = true
  (* match msg with 
     RouteMonitor _pld -> 
      if _pld.peer_hdr.typ = BMP_MSG_PEER_TYPE_GLOBAL && _pld.peer_hdr.peer_id = (Ipaddr.V4.of_string_exn "100.64.0.24") then true else false
     | Stat _ -> false
     | _ -> true *)
  in
  msgs |> (Seq.filter filter_msg) |> Seq.iter print_msg;
  Unix.close fd;
  print_endline "Connection closed";
  Thread.exit
;;

let create_socket listen_address port backlog =
  let open Unix in
  let sock = socket PF_INET SOCK_STREAM 0 in
  let bind_addr = ADDR_INET(listen_address, port) in
  setsockopt sock SO_REUSEADDR true;
  bind sock bind_addr;
  Printf.printf "Listening on %s\n%!" @@ show_sockaddr bind_addr;
  listen sock backlog;
  sock

let () = 
  let _ = Printexc.record_backtrace true in
  let sock = create_socket Unix.inet_addr_any 5000 10 in
  while true do
    let c = Unix.accept sock in 
    let _ = Thread.create accept_connection c in
    ()
  done
