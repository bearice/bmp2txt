open Bmp;;
type bmp_metadata = {from: Unix.sockaddr; seq: int} ;;



let show_sockaddr from = match from with 
    Unix.ADDR_INET (addr,port) -> String.concat ":" [(Unix.string_of_inet_addr addr); (Int.to_string port)] 
  | Unix.ADDR_UNIX name -> name
;;

let print_msg ({from;seq},msg) = 
  print_int seq ;
  print_string " " ;
  print_string @@ show_sockaddr from ;
  print_string " " ;
  print_endline (show_bmp_msg msg) ;
;;

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

let socket_main () = 
  let _ = Printexc.record_backtrace true in
  let sock = create_socket Unix.inet_addr_any 5000 10 in
  while true do
    let c = Unix.accept sock in 
    let _ = Thread.create accept_connection c in
    ()
  done

open Lwt
open Kafka.Metadata

let rec split_hdr msg offset =
  let i = Bytes.index_from msg offset '\n' in
  if '\n' = Bytes.get msg @@ i+1 then
    (* let _ = print_endline @@ Bytes.to_string @@ Bytes.sub msg 0 i in *)
    Bytes.sub msg (i+2) ((Bytes.length msg)-(i+2))
  else
    split_hdr msg @@ i+1

let parse_msg msg = 
  let buf = Bytes.of_string msg in 
  let buf = split_hdr buf 0 in
  let raw = read_bmp_msg_raw buf in
  try
    let msg = read_bmp_msg raw in
    Lwt_io.printl @@ show_bmp_msg msg;
    (* Lwt.return () *)
  with e ->
    let _ = print_endline @@ show_bmp_msg_raw raw in
    Utils.debug_hex_dump buf;
    raise e

let print_msg = function
  | Kafka.Message (_,_,_,msg,_) -> parse_msg msg
  | Kafka.PartitionEnd (topic,partition,offset) ->
    Lwt_io.printf "%s,%d,%Ld (EOP)\n%!" (Kafka.topic_name topic) partition offset

let kafka_main () =
  (* Prepare a consumer handler *)
  let consumer = Kafka.new_consumer ["metadata.broker.list","b-3.infra-monitor.prd4u3.c4.kafka.ap-northeast-1.amazonaws.com:9092"] in
  let topic = Kafka.new_topic consumer "openbmp.bmp_raw" ["auto.commit.enable","false"] in
  let queue = Kafka.new_queue consumer in
  let partitions = (Kafka.topic_metadata consumer topic).topic_partitions in
  let timeout_ms = 1000 in
  let msg_count = 10 in
  let start () =
    List.iter (fun partition -> Kafka.consume_start_queue queue topic partition Kafka.offset_beginning) partitions
    |> return
  in
  let rec loop () = 
    Kafka_lwt.consume_batch_queue ~timeout_ms ~msg_count queue
    >>=
    Lwt_list.iter_s print_msg
    >>=
    loop
  in
  let term () =
    Kafka.destroy_topic topic;
    Kafka.destroy_queue queue;
    Kafka.destroy_handler consumer;
    return ()
  in
  Lwt_main.run (start () >>= loop >>= term)
;;
let () = 
  Printexc.record_backtrace true;
  kafka_main ()
