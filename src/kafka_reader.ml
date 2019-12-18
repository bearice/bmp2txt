open Bmp
open Lwt
open Kafka.Metadata

type bmp_metadata = {from: string; seq: int} ;;
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
    Lwt.return @@ read_bmp_msg raw
  (* Lwt.return () *)
  with e ->
    let _ = print_endline @@ show_bmp_msg_raw raw in
    Utils.debug_hex_dump buf;
    raise e

let print_msg = function
  | Kafka.Message (_,_,_,msg,_) -> 
    parse_msg msg >>= fun msg -> Lwt_io.printl @@ bmp_msg_to_json_string msg ;
    (* | Kafka.PartitionEnd (topic,partition,offset) ->
       Lwt_io.printf "%s,%d,%Ld (EOP)\n%!" (Kafka.topic_name topic) partition offset *)
  | _ -> return ()

let main ?(msg_count=10) ?(timeout_ms=1000) ~server ~topic =
  (* Prepare a consumer handler *)
  let consumer = Kafka.new_consumer ["bootstrap.servers",server] in
  let topic = Kafka.new_topic consumer topic ["auto.commit.enable","false"] in
  let queue = Kafka.new_queue consumer in
  let partitions = (Kafka.topic_metadata consumer topic).topic_partitions in
  let start () =
    List.iter (fun partition -> Kafka.consume_start_queue queue topic partition Kafka.offset_end) partitions;
    return ()
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