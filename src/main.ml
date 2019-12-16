
let () = 
  Printexc.record_backtrace true;
  Kafka_reader.kafka_main ()
