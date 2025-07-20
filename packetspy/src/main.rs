use clap::Parser;
use pnet::datalink::{self,Channel,Config};
use std::process;

#[derive(Parser,Debug)]
struct Args{
    #[arg(short,long)]
    interface:String,
}

fn main(){
    let args=Args::parse();

    let interfaces=datalink::interfaces();
    let interface=interfaces.iter()
        .find(|iface| iface.name==args.interface)
        .unwrap_or_else(||{
            eprintln!("Interface {} not found",args.interface);
            std::process::exit(1);
        });


    println!("Listeneing on interface: {}",args.interface);

    let mut config=Config::default();
    config.read_timeout=Some(std::time::Duration::from_millis(1000));

    let (mut _tx,mut rx)=match datalink::channel(interface,config){
        Ok(Channel::Ethernet(tx,rx))=>(tx,rx),
        Ok(_) => {
            eprintln!("Unsupported channel type");
            process::exit(1);
        },
        Err(e)=>{
            eprintln!("Failed to create a datalink channel: {}",e);
            process::exit(1);
        }
    };

    println!("🟢 Capturing packets... Press Ctrl+C to stop.\n");

    loop{
        match rx.next(){
            Ok(packet)=>{
                println!("📦 Packet captured: {} bytes",packet.len());

            }
            Err(e)=>{
                eprintln!("❌ Error receiving packet: {}",e);
            }
        }
    }

}
