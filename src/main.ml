
let () = 
  Printexc.record_backtrace true;
  (* let config = ref None in  *)
  let input = ref "unknown" in
  let listen = ref "0.0.0.0:1590" in
  let server = ref "localhost:9092" in
  let topic = ref "openbmp.bmp_raw" in 
  let batch_count = ref 10 in
  let timeout = ref 1000 in 
  (* let set_string r v = r := v in *)
  let speclist = Arg.align [
      (* ("--config", Arg.String (fun s->config:=Some s), "<file> Config file"); *)
      ("--input", Arg.Symbol (["socket"; "kafka"], (fun s->input:=s)), "Input plugin");
      ("--socket-listen", Arg.Set_string listen, "[0.0.0.0:1590] Socket bind address");
      ("--kafka-server", Arg.Set_string server, "[localhost:9092] Kafka bootstrap server");
      ("--kafka-topic", Arg.Set_string topic, "[openbmp.bmp_raw] Kafka topic");
      ("--kafka-batch-count", Arg.Set_int batch_count, "[10] Kafka batch fetch limit");
      ("--kafka-timeout", Arg.Set_int timeout, "[1000] Kafka connection timeout in ms");
      ("-help", Arg.Unit (fun()->()), "");
    ] in
  let usage_msg = "Usage: bmp2txt <options>" in 
  Arg.parse speclist print_endline usage_msg;
  (* let () = match !config with
     | None -> ()
     | Some c -> 
      print_endline c;
      let argv = Arg.read_arg c in
      Arg.current := 0;
      Arg.parse_argv argv speclist print_endline usage_msg
     in *)
  match !input with 
  | "kafka" -> Kafka_reader.main ~server:!server ~topic:!topic ~msg_count:!batch_count ~timeout_ms:!timeout
  | "socket" -> Socket_reader.main ~bind:!listen
  | _ -> Arg.usage speclist usage_msg