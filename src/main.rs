use aes_gcm::{Aes128Gcm, Key, Nonce}; // Or `Aes128Gcm`
use aes_gcm::aead::{Aead, NewAead, Payload};

use std::io::prelude::*;
use std::io::{Error, BufWriter, Write, Cursor};
use std::net::UdpSocket;
use bitbuffer::{BitReadBuffer, LittleEndian, BitReadStream, BitRead, BitWriteStream};
use bitstream_io::BitWriter;

const LZSS_LOOKSHIFT: u32 = 4;
//const LZSS_LOOKAHEAD: u32 = 1 << LZSS_LOOKSHIFT;

static mut alla: bool = false;

fn decode(input: &[u8], output: &mut Vec<u8>) -> Result<(), std::io::Error> {
    //let buffassad = BitReadBuffer::new(input, LittleEndian);
    //let mut input_reader = BitReadStream::new(buffassad);

    let mut get_cmd_byte = 0u32;
    let mut cmd_byte = 0u32;
    let mut i = 0usize;

    loop {
        if get_cmd_byte == 0 {
            cmd_byte = input[i] as u32;
            i += 1;
        }
        get_cmd_byte = (get_cmd_byte+1)&0x7;

        if cmd_byte & 1 != 0 {
            let pos = ((input[i] as u32) << LZSS_LOOKSHIFT) | ((input[i+1] as u32) >> LZSS_LOOKSHIFT);
            i += 1;
            let count = (input[i] & 0xF) + 1;
            i += 1;
            if count == 1 {
                break;
            }
            let start_pos = output.len() - (pos as usize) - 1;
            for ii in 0..count as usize {
                output.push(output[start_pos + ii]);
            }
        } else {
            output.push(input[i]);
            i += 1;
        }

        cmd_byte = cmd_byte >> 1;
    }
    
    Ok(())
}

fn forge_packet(input: &[u8], in_seq: u32, out_seq: u32, idk: u32) -> Vec<u8> {
    //let mut stream = BitWriteStream::new(LittleEndian);
    let mut stream = BitWriter::endian(Vec::new(), bitstream_io::LittleEndian);
    
    //stream.write_int(in_seq, 32).unwrap();
    //stream.write_int(out_seq, 32).unwrap();
    stream.write(32, in_seq);
    stream.write(32, out_seq);

    //stream.write_int(1u16, 8).unwrap(); // flags, reliable data
    stream.write(8, 0); // no reliable
    //stream.write(8, 1); // reliable subchans and recv lists

    //stream.write_int(0u16, 9).unwrap();
    //stream.write_bool(false).unwrap(); // unk
    stream.write(9, 0);
    stream.write_bit(false);

    stream.write_bytes(input);

    stream.byte_align();
    stream.into_writer()

    // Shut you not, client just refuses to parse fucking subchans...
    /*

    //stream.write_int(0u8, 8).unwrap(); // v6
    //stream.write_bool(false).unwrap(); // unk, perhaps no checksum?
    //stream.write_int(idk, 32).unwrap();
    stream.write(8, 0); // v6
    stream.write_bit(false); // ergh?

    // first and only subchan rn
    //stream.write_bool(true).unwrap(); // m?
    //stream.write_int(input.len() as u32, 18).unwrap();
    //stream.write_bool(false).unwrap(); // not compressed
    //stream.write_bytes(input).unwrap();
    stream.write_bit(true); // single block
    stream.write(18, input.len() as u32);
    stream.write_bit(false); // unc
    stream.write_bytes(input);

    // close subchan
    //stream.write_bool(false).unwrap();
    stream.write_bit(false);

    stream.byte_align();

    stream.into_writer()
    */
}

fn forge_data_block(input: &[u8], a2: u8, a4: u8) -> Vec<Vec<u8>> {
    let mut vec: Vec<Vec<u8>> = Vec::new();
    let mut pos = 0u32;
    let mut blocknum = 0u8;

    loop {
        let mut sz = (input.len() as u32) - pos;
        if sz > 1024 {
            sz = 1024;
        }
        else if sz == 0 {
            break;
        }

        let mut stream = BitWriter::endian(Vec::new(), bitstream_io::LittleEndian);

        stream.write(32, 0xFFFFFFFFu32);
        stream.write(8, 77); // 'M'

        stream.write(8, 0); // a2

        stream.write(32, input.len() as u32);

        stream.write(8, 0); // a4
        stream.write(8, blocknum); // cur block
        
        stream.write(32, sz);

        stream.write_bytes(&input[pos as usize..(pos+sz) as usize]);

        vec.push(stream.into_writer());

        blocknum += 1;
        pos += sz;
    }

    vec
}

fn parse(socket: &UdpSocket, src: &std::net::SocketAddr, input: &Vec<u8>, in_seq: u32, out_seq: u32, idk: u32) {
    let buff = BitReadBuffer::new(input, LittleEndian);
    let mut stream = BitReadStream::new(buff);

    loop {
        if stream.bits_left() < 6 {
            break
        }

        let id: u32 = stream.read_int(6).unwrap();
        match id {
            0 => {
                // nop
                continue;
            }
            5 => {
                // SetConvar
                let num: u8 = stream.read_int(8).unwrap();
                println!("SetConvar {}", num);
                for _ in 0..num {
                    let key = stream.read_string(None).unwrap();
                    let val = stream.read_string(None).unwrap();
                    println!("\t'{}' '{}'", key, val);
                }
            }
            6 => {
                // SignonState
                let state: u8 = stream.read_int(8).unwrap();

                let server_count: i32 = stream.read_int(32).unwrap();
                let unk32_28: u32 = stream.read_int(32).unwrap();
                let unk32_48: u32 = stream.read_int(32).unwrap();
                println!("SignonState {} | {} {} {}", state, server_count, unk32_28, unk32_48);
                if unk32_48 > 0 {
                    let bytes = stream.read_bytes(unk32_48 as usize);
                    println!("\t{:02X?}", bytes);
                }

                let maplen: u32 = stream.read_int(32).unwrap(); // 0x68
                if maplen > 0 {
                    let bytes = stream.read_bytes(maplen as usize);
                    println!("\t{:02X?}", bytes);
                }

                let gamemode: u32 = stream.read_int(32).unwrap(); // 0x88
                if gamemode > 0 {
                    let bytes = stream.read_bytes(gamemode as usize);
                    println!("\t{:02X?}", bytes);
                }

                let unk: u8 = stream.read_int(8).unwrap();
                let ver = stream.read_string(None).unwrap();
                let vnum: u32 = stream.read_int(32).unwrap();
                let playlist = stream.read_string(None).unwrap();
                let unk2: u32 = stream.read_int(32).unwrap();
                println!("{} '{}' {} '{}' {}", unk, ver, vnum, playlist, unk2);

                // Connected
                if state == 2 {
                    // Send shit
                    //let mut buf = BitWriteStream::new(LittleEndian);
                    let mut buf = BitWriter::endian(Vec::new(), bitstream_io::LittleEndian);
                    //buf.write_int(5, 6);

                    //*
                    // SVC_PersistenceDefFile | SVC_UseCachedPersistenceDefFile
                    //*
                    {
                        //def file
                        buf.write(6, 0x17);
                        buf.write(32, 299); // version
                        let file = std::fs::read("D:\\Downloads\\pdef_test.bz2").unwrap();
                        buf.write(16, file.len() as u32); // len
                        buf.write_bytes(&file); // file
                    } // */
                    // SVC_PersistenceBaseline ???

                    //sv_send playlists is 1 by default so yeah
                    {
                        // TODO: send playlist
                    }

                    // useless print...

                    const playlist: &[u8; 31] = b"Load a map on the command line\0";

                    // playlist change, trips over this
                    buf.write(6, 0x1d); // SVC_PlaylistChange
                    buf.write_bytes(playlist.as_ref()); // WHAT THE FUCK
                    //buf.write_bytes(b"Load a map on the command line\0"); // WHAT THE FUCK
                    
                    // no overrides, this code will also trip over
                    //buf.write(6, 0x1f);
                    //buf.write(8, 0);
                    
                    // playlist player counts
                    //buf.write(6, 0x20);
                    //buf.write(32, 0); // !!!TODO!!!

                    // svc_ServerInfo
                    {
                        buf.write(6, 0x7);
                        buf.write(16, 2001); // proto
                        buf.write(32, 2); // server num
                        buf.write_bit(false); // b1
                        buf.write_bit(false); // b2
                        buf.write_bit(true); // dedicated for sure
                        buf.write_signed(32, -1); // Used to be client.dll CRC.  This was far before signed binaries, VAC, and cross-platform play
                        buf.write(32, 0); // instance type
                        buf.write(16, 277); // unk3 used in fast_log2 and sets some vals
                        buf.write(32, 1762522675); // unk4 unused???

                        buf.write(8, 0); // numplayers or player slot?
                        buf.write(8, 12); // maxplayers for sure

                        // 0.01666666753590106964111328125
                        //buf.write(32, 1015580809); // Tick interval
                        buf.write(32, 0x3dcccccd); // Tick interval
                        //buf.write_bytes(&(0.2f32).to_le_bytes()); // doesn't work wtf
                        buf.write(8, 119); // OS 'w', can make Linux or MacOS for lulz

                        buf.write_bytes(b"r1_dlc1\0"); // game dir aka game name
                        buf.write_bytes(b"mp_lobby\0"); // map
                        buf.write_bytes(b"tdm\0"); // gamemode
                        buf.write_bytes(b"\0"); // unk9
                        buf.write_bytes(b"R1 Test\0"); // hostname???
                        buf.write_bytes(b"k0k_succ\0"); // should be sky name...

                        // one of the unknowns is actually an sv_skyname...
                    }

                    //*
                    {
                        // string table for downloadables
                        buf.write(6, 0xC);
                        buf.write_bytes(b"downloadables\0");
                        
                        buf.write(16, 8192);
                        buf.write(14, 20); // fast_log2(8192)+1
                        
                        buf.write(21, 2120); // data len in bits

                        buf.write_bit(false); // user data fixed size

                        buf.write_bit(true); // compressed?
                        buf.write_bit(true);

                        // TODO: write data
                        // This is perfectly aligned
                        buf.write_bytes(&[ 192, 1, 0, 0, 1, 1, 0, 0, 76, 90, 83, 83, 192, 1, 0, 0, 0, 214, 22, 6, 55, 247, 210, 6, 247, 0, 197, 246, 38, 38, 150, 231, 34, 54, 0, 7, 7, 96, 99, 102, 103, 47, 99, 0, 112, 117, 95, 108, 101, 118, 101, 108, 0, 95, 48, 95, 112, 99, 46, 101, 107, 0, 118, 0, 17, 128, 0, 0, 0, 128, 0, 218, 179, 31, 240, 7, 249, 53, 55, 0, 231, 82, 182, 102, 7, 16, 1, 8, 1, 1, 50, 208, 151, 230, 255, 124, 112, 49, 65, 2, 125, 117, 154, 119, 161, 15, 2, 125, 96, 64, 14, 46, 86, 123, 112, 50, 2, 124, 0, 32, 21, 176, 114, 233, 23, 2, 125, 16, 219, 96, 27, 106, 124, 32, 103, 8, 31, 3, 23, 156, 0, 57, 222, 176, 31, 23, 243, 5, 55, 2, 230, 3, 41, 64, 59, 135, 224, 249, 113, 129, 5, 174, 249, 138, 209, 134, 31, 55, 2, 141, 0, 16, 222, 155, 209, 120, 32, 109, 101, 6, 109, 5, 191, 3, 37, 158, 146, 162, 130, 47, 129, 5, 190, 112, 228, 185, 119, 254, 114, 5, 190, 32, 255, 5, 178, 158, 47, 5, 190, 224, 175, 48, 181, 96, 250, 65, 5, 191, 3, 40, 127, 62, 16, 119, 199, 63, 25, 3, 45, 184, 186, 103, 8, 107, 251, 147, 5, 189, 128, 101, 140, 116, 8, 162, 63, 57, 2, 141, 0, 232, 31, 219, 8, 251, 147, 52, 5, 29, 106, 171, 54, 7, 1, 0, 0 ]);
                        /*let data: [u8; 265] = [ 192, 1, 0, 0, 1, 1, 0, 0, 76, 90, 83, 83, 192, 1, 0, 0, 0, 214, 22, 6, 55, 247, 210, 6, 247, 0, 197, 246, 38, 38, 150, 231, 34, 54, 0, 7, 7, 96, 99, 102, 103, 47, 99, 0, 112, 117, 95, 108, 101, 118, 101, 108, 0, 95, 48, 95, 112, 99, 46, 101, 107, 0, 118, 0, 17, 128, 0, 0, 0, 128, 0, 218, 179, 31, 240, 7, 249, 53, 55, 0, 231, 82, 182, 102, 7, 16, 1, 8, 1, 1, 50, 208, 151, 230, 255, 124, 112, 49, 65, 2, 125, 117, 154, 119, 161, 15, 2, 125, 96, 64, 14, 46, 86, 123, 112, 50, 2, 124, 0, 32, 21, 176, 114, 233, 23, 2, 125, 16, 219, 96, 27, 106, 124, 32, 103, 8, 31, 3, 23, 156, 0, 57, 222, 176, 31, 23, 243, 5, 55, 2, 230, 3, 41, 64, 59, 135, 224, 249, 113, 129, 5, 174, 249, 138, 209, 134, 31, 55, 2, 141, 0, 16, 222, 155, 209, 120, 32, 109, 101, 6, 109, 5, 191, 3, 37, 158, 146, 162, 130, 47, 129, 5, 190, 112, 228, 185, 119, 254, 114, 5, 190, 32, 255, 5, 178, 158, 47, 5, 190, 224, 175, 48, 181, 96, 250, 65, 5, 191, 3, 40, 127, 62, 16, 119, 199, 63, 25, 3, 45, 184, 186, 103, 8, 107, 251, 147, 5, 189, 128, 101, 140, 116, 8, 162, 63, 57, 2, 141, 0, 232, 31, 219, 8, 251, 147, 52, 5, 29, 106, 171, 54, 7, 1, 0, 0 ];
                        for i in data.iter() {
                            buf.write(8, *i);
                        }*/
                    }

                    //*
                    {
                        // string table for modelprecache
                        buf.write(6, 0xC);
                        buf.write_bytes(b"modelprecache\0");
                        
                        buf.write(16, 1024);
                        buf.write(11, 2); // fast_log2(1024)+1
                        
                        buf.write(21, 165); // data len in bits

                        buf.write_bit(true); // user data fixed size
                        buf.write(12, 1); // user data size bytes
                        buf.write(4, 2); // user data bits

                        buf.write_bit(false); // compressed?
                        buf.write_bit(true);

                        // this is not aligned...
                        buf.write_bytes(&[ 6, 144, 181, 133, 193, 205, 189, 180, 193, 125, 177, 189, 137, 137, 229, 185, 136, 205, 193, 1 ]);
                        buf.write(5, 28); // 165%8 = 5
                    }
                    // */

                    /*
                    buf.write(6, 1);
                    buf.write_bytes("Охуенен и пиздат
                    Я известен и богат
                    В моей голове дыра, wha
                    Я — дегенерат
                    Охуенен и пиздат
                    Я известен и богат
                    В моей голове дыра, wha (Прр)
                    Я — дегенерат (Е, окей)
                    Выхожу на блок (Окей), е
                    Цепи, будто лёд (Ice), е
                    У меня бабло (Ага)
                    Я будто Пабло (Few-few-few)
                    А, сука, прыгнул в самолёт, е (Фрр)
                    Будто вертолёт
                    Что блять, на мне твоя hoe, е, она дала топ
                    Ха, бам! Снова на сцене, ха, бум!
                    Будто бездельник
                    Ха, бум! Сука в отеле, ха, бум! На постели
                    Ха, е, да, мулатка, е, е (У, у), шоколадка
                    А, е, шакалака, бум-бум, шакалака
                    Я залетаю к феминисткам, нахуй, прямо с калашом (Ра-та-та-та)
                    Сука, были б вы людьми, у нас всё было хорошо (Оке)
                    Ха, дыщ — по ебалу, ха, дыщ — вам чё мало? Эй
                    Выбегаю нахуй и туда летит граната
                    Нахуй вы все поменялись, не так, блять, как хочу?
                    А если ты не понимаешь, но, поверь, мне похую (Поверь, мне похую)
                    Бля, би-аби-бэ-хиба-бибе-бе-бэ (Бу-э)
                    Снова спел хуйню и заработал много денег! Ха-ха-ха! (Победа)
                    Охуенен и пиздат
                    Я известен и богат
                    В моей голове дыра, wha
                    Я — дегенерат
                    Охуенен и пиздат
                    Я известен и богат
                    В моей голове дыра, wha
                    Я — дегенерат
                    Охуенен и пиздат
                    Я известен и богат
                    В моей голове дыра, wha
                    Я — дегенерат
                    Охуенен и пиздат
                    Я известен и богат
                    В моей голове дыра, wha\0".as_bytes());
                    buf.byte_align(); // */

                    // SignonState
                    {
                        buf.write(6, 6);

                        buf.write(8, 3); // signonstate - NEW
                        buf.write(32, 2); // server count
                        buf.write(32, 0); // unk
                        buf.write(32, 0); // unk & len

                        buf.write(32, 9);
                        buf.write_bytes(b"mp_lobby\0");

                        buf.write(32, 4);
                        buf.write_bytes(b"tdm\0");

                        buf.write(8, 1);
                        buf.write_bytes(b"stable\0"); // ver
                        buf.write(32, 1922);
                        buf.write_bytes(playlist); // playlist
                        buf.write(32, 895261362);
                    }

                    //buf.write_int(1u32, 6).unwrap();
                    //buf.write_string("s00kas00kas00kas00kas00kas00kas00kas00kas00ka", None).unwrap();

                    buf.byte_align();
                    let bytes = buf.into_writer();
                    //println!("{:02X?} {}", bytes, bytes.len());

                    let datas = forge_data_block(bytes.as_slice(), 0, 0);

                    for i in datas {
                        let key = Key::from_slice(b"\xc5\xf8\xb2\xd2+\x11t]\xc7\xd0xwu\xebHP");
                        let aad = b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10".as_ref();
                        let cipher = Aes128Gcm::new(key);

                        let nonce = Nonce::from_slice(&bytes[..12]);
                        let enc = cipher.encrypt(nonce, Payload {
                            msg: i.as_slice(),
                            aad: aad,
                        }).expect("Enc error!");
                        //println!("{:02X?}", enc);

                        let msg = [&bytes[..12], &enc[enc.len()-16..], &enc[..enc.len()-16]].concat();
                        //println!("{:02X?}", msg);
                        socket.send_to(&msg, src).expect("Data send failure lmfao");
                    }

                    /*let packet = forge_packet(&bytes, in_seq+229, out_seq+228, idk);
                    println!("{:02X?} {}", packet, packet.len());
                    
                    let key = Key::from_slice(b"\xc5\xf8\xb2\xd2+\x11t]\xc7\xd0xwu\xebHP");
                    let aad = b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10".as_ref();
                    let cipher = Aes128Gcm::new(key);

                    let nonce = Nonce::from_slice(&bytes[..12]);
                    let enc = cipher.encrypt(nonce, Payload {
                        msg: packet.as_slice(),
                        aad: aad,
                    }).expect("Enc error!");
                    //println!("{:02X?}", enc);

                    let msg = [&bytes[..12], &enc[enc.len()-16..], &enc[..enc.len()-16]].concat();
                    //println!("{:02X?}", msg);
                    socket.send_to(&msg, src).expect("Data send failure lmfao");*/
                }
            }
            7 => {
                //svc_UserMessage
                let id: u8 = stream.read_int(8).unwrap();
                let size: usize = stream.read_int(12).unwrap();
                let buf = stream.read_bits(size).unwrap();

                println!("svc_UserMessage {} {}", id, size);
            }
            44 => {
                // clc_ClientInfo
                let unk: u32 = stream.read_int(32).unwrap(); // count?
                let send_table_crc: u32 = stream.read_int(32).unwrap(); // CRC
                let unk1: u32 = stream.read_int(32).unwrap();
                let b = stream.read_bool().unwrap(); // hltv?
                let unk2: u32 = stream.read_int(32).unwrap(); // UID?
                let s = stream.read_string(None).unwrap();

                println!("clc_ClientInfo {} {} {} {} {} {}", unk, send_table_crc, unk1, b, unk2, s);

                for _ in 0..4 {
                    let b = stream.read_bool().unwrap();
                    if b {
                        println!("\ttrue {}", stream.read_int::<u32>(32).unwrap());
                    } else {
                        println!("\tfalse");
                    }
                }
            }
            55 => {
                let size: usize = stream.read_int(16).unwrap();
                let data = stream.read_bytes(size);

                println!("clc_PersistenceClientToken {} {:02X?}", size, data);

                // good opportunity to ~~shit my pants~~ set sign on to PRESPAWN?

                unsafe {
                    if alla {
                        continue;
                    }
                    alla = true;
                }

                let mut buf = BitWriter::endian(Vec::new(), bitstream_io::LittleEndian);

                // SignonState
                {
                    buf.write(6, 6);

                    buf.write(8, 4); // signonstate - PRESPAWN
                    buf.write(32, 2); // server count
                    buf.write(32, 0); // unk
                    buf.write(32, 0); // unk & len

                    buf.write(32, 9);
                    buf.write_bytes(b"mp_lobby\0");

                    buf.write(32, 4);
                    buf.write_bytes(b"tdm\0");

                    buf.write(8, 1);
                    buf.write_bytes(b"stable\0"); // ver
                    buf.write(32, 1922);
                    buf.write_bytes(b"Load a map on the command line\0"); // playlist
                    buf.write(32, 895261362);
                }

                // SignonState
                {
                    buf.write(6, 6);

                    // can't go any further
                    buf.write(8, 6); // signonstate - SPAWN
                    buf.write(32, 2); // server count
                    buf.write(32, 0); // unk
                    buf.write(32, 0); // unk & len

                    buf.write(32, 9);
                    buf.write_bytes(b"mp_lobby\0");

                    buf.write(32, 4);
                    buf.write_bytes(b"tdm\0");

                    buf.write(8, 1);
                    buf.write_bytes(b"stable\0"); // ver
                    buf.write(32, 1922);
                    buf.write_bytes(b"Load a map on the command line\0"); // playlist
                    buf.write(32, 895261362);
                }

                buf.byte_align();
                let bytes = buf.into_writer();
                //println!("{:02X?} {}", bytes, bytes.len());

                /*let datas = forge_data_block(bytes.as_slice(), 0, 1);

                for i in datas {
                    let key = Key::from_slice(b"\xc5\xf8\xb2\xd2+\x11t]\xc7\xd0xwu\xebHP");
                    let aad = b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10".as_ref();
                    let cipher = Aes128Gcm::new(key);

                    let nonce = Nonce::from_slice(&bytes[..12]);
                    let enc = cipher.encrypt(nonce, Payload {
                        msg: i.as_slice(),
                        aad: aad,
                    }).expect("Enc error!");
                    //println!("{:02X?}", enc);

                    let msg = [&bytes[..12], &enc[enc.len()-16..], &enc[..enc.len()-16]].concat();
                    //println!("{:02X?}", msg);
                    socket.send_to(&msg, src).expect("Data send failure lmfao");
                } // */

                //*
                let datas = forge_packet(bytes.as_slice(), in_seq+2, out_seq+2, 0); //forge_data_block(bytes.as_slice());

                let key = Key::from_slice(b"\xc5\xf8\xb2\xd2+\x11t]\xc7\xd0xwu\xebHP");
                let aad = b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10".as_ref();
                let cipher = Aes128Gcm::new(key);

                let nonce = Nonce::from_slice(&bytes[..12]);
                let enc = cipher.encrypt(nonce, Payload {
                    msg: datas.as_ref(),
                    aad: aad,
                }).expect("Enc error!");
                //println!("{:02X?}", enc);

                let msg = [&bytes[..12], &enc[enc.len()-16..], &enc[..enc.len()-16]].concat();
                //println!("{:02X?}", msg);
                socket.send_to(&msg, src).expect("Data send failure lmfao");
                // */
            }
            _ => {
                println!("Unknown Net MSG {}", id);
                break;
            }
        }
    }

    println!("END");
}

fn main() -> Result<(), Error> {
    
    let key = Key::from_slice(b"\xc5\xf8\xb2\xd2+\x11t]\xc7\xd0xwu\xebHP");
    let aad = b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10".as_ref();
    let cipher = Aes128Gcm::new(key);

    /*let nonce = Nonce::from_slice(b"\x90\xed#\x1a\x97\x84\x0e\x0e\x8aI\xeb6");

    let ciphertext = cipher.encrypt(nonce, 
        Payload {
            msg: b"\xff\xff\xff\xffHconnect0x00000000\x00".as_ref(),
            aad: b"\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\x0c\r\x0e\x0f\x10".as_ref(),
        }).expect("Brih");

    println!("{:02X?}", ciphertext);*/

    let mut socket = UdpSocket::bind("127.0.0.1:28115").expect("Brih");

    println!("Bound!");

    loop {
        let mut buf = [0; 4096];
        let (amt, src) = socket.recv_from(&mut buf).expect("Brih");

        let buf = &mut buf[..amt];
        //println!("{:02X?}", buf);

        let nonce = Nonce::from_slice(&buf[..12]);
        let msg = &[&buf[28..], &buf[12..28]].concat();
        let mut plaintext = cipher.decrypt(nonce, 
            Payload {
                msg: msg,
                aad: aad,
            }).expect("Bruh");

        //println!("{:02X?}", plaintext);

        //let sz = plaintext.len();

        //if idr == 0xFFFFFFFF {
        // FUCKING SPLIT PACKET DUDE
        if plaintext[0] == 0xfe && plaintext[3] == 0xff {
            let bitbuf = BitReadBuffer::new(&plaintext, LittleEndian);
            let mut stream = BitReadStream::new(bitbuf);

            let k0k: u32 = stream.read_int(32).unwrap();
            let seq: u32 = stream.read_int(32).unwrap();
            let packet_id: u32 = stream.read_int(16).unwrap();
            let split_size: usize = stream.read_int(16).unwrap();

            println!("Split {} | {} | {}", k0k, seq, split_size);

            let mut res: Vec<u8> = Vec::new();
            res.append(&mut plaintext[12..].as_ref().to_vec());

            loop {
                if res.len() >= split_size {
                    break
                }

                let mut buf = [0; 4096];
                let (amt, src) = socket.recv_from(&mut buf).expect("Brih");

                let buf = &mut buf[..amt];
                //println!("{:02X?}", buf);

                let nonce = Nonce::from_slice(&buf[..12]);
                let msg = &[&buf[28..], &buf[12..28]].concat();
                let p = cipher.decrypt(nonce, 
                    Payload {
                        msg: msg,
                        aad: aad,
                }).expect("Bruh");
                
                res.append(&mut p[12..].as_ref().to_vec());
            }

            let mut buf = [0; 4096];
            let (amt, src) = socket.recv_from(&mut buf).expect("Brih");

            //continue;

            plaintext = res;
        }

        if plaintext[..4] == [0xFFu8; 4] {
            let cmd = plaintext[4];
            println!("Connectionless packet! {}", cmd);
            if cmd == 0x48 {
                println!("H packet!");
                
                let header = [0xFFu8; 4];
                let code = [73u8; 1];
                let challenge = [0u8; 4];
                let empty_string = [0u8; 1];
                let protocol = [0xd1, 7, 0, 0]; // 2.0.0.1
                //let k0k = [0u8; 19]; //[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
                let msg = [
                    header.as_ref(), // connectionless
                    &code, // 'I'
                    // ---
                    &challenge, // random 32 bits?
                    // ---
                    &plaintext[5..], // what we sent
                    &protocol,
                    &empty_string, // empty string... literally...
                    &empty_string, // VAC?
                    // ---
                    &header, // last 64 bits
                    &header
                ].concat();
                println!("{:02X?}", msg);
                
                let nonce = Nonce::from_slice(&buf[..12]);
                let enc = cipher.encrypt(nonce, Payload {
                    msg: &msg,
                    aad: aad,
                }).expect("Enc error!");
                println!("{:02X?}", enc);

                let msg = [&buf[..12], &enc[enc.len()-16..], &enc[..enc.len()-16]].concat();
                println!("{:02X?}", msg);
                socket.send_to(&msg, src).expect("Data send failure lmfao");
            }
            else if cmd == 65 { // 'A' aka C2S_CONNECT
                println!("A packet!");
                
                let bitbuf = BitReadBuffer::new(&plaintext[5..], LittleEndian);
                let mut stream = BitReadStream::new(bitbuf);
                
                let net_proto: u32 = stream.read_int(32).unwrap();
                let auth_proto: u32 = stream.read_int(32).unwrap();
                //println!("{} {}", net_proto, auth_proto);
                if net_proto != 1040 || auth_proto != 2001 {
                    // TODO reject
                } else {

                    let challenge: u32 = stream.read_int(32).unwrap();
                    let idk: u32 = stream.read_int(32).unwrap();
                    
                    let isfren = stream.read_int::<u64>(32).unwrap() == 0;

                    let uid: u64 = stream.read_int(64).unwrap();

                    // Read NT string...
                    let nick = stream.read_string(None).unwrap();
                    if nick.len() > 64 {
                        // TODO reject
                    }
                    
                    println!("{} {} {} {} | '{}'", challenge, idk, isfren, uid, nick);

                    let pass = stream.read_string(None).unwrap();
                    let playlist = stream.read_string(None).unwrap();
                    let isfren2 = stream.read_int::<u8>(8).unwrap() == 1;
                    println!("'{}' | '{}' | {}", pass, playlist, isfren2);

                    if isfren2 {
                        let fren: u64 = stream.read_int(64).unwrap();
                        println!("FREN!: {}", fren);
                    }

                    let serverfilter = stream.read_string(None).unwrap();

                    let playlist_ver: u32 = stream.read_int(32).unwrap();
                    let ksh_pers_ver: u32 = stream.read_int(32).unwrap();

                    let idk1: u32 = stream.read_int(32).unwrap();
                    let idk2: u32 = stream.read_int(32).unwrap();

                    let splitscreen: u8 = stream.read_int(8).unwrap();
                    if splitscreen != 1 {
                        // TODO reject
                    }

                    println!("'{}' | {} {} | {} {} | {}", serverfilter, playlist_ver, ksh_pers_ver, idk1, idk2, splitscreen);

                    // TODO cvars
                    let id: u32 = stream.read_int(6).unwrap();
                    if id != 56 {
                        // TODO: reject
                    }
                    let count: u8 = stream.read_int(8).unwrap();
                    println!("CVars: {}", count);
                    for _ in 0..count {
                        let key = stream.read_string(None).unwrap();
                        let val = stream.read_string(None).unwrap();
                        println!("\t'{}' '{}'", key, val);
                    }

                    // bit - LV
                    // u8 - idk3
                    let lv = stream.read_int::<u8>(1).unwrap() == 1;
                    let idk3: u8 = stream.read_int(8).unwrap();
                    if idk3 != 1 {
                        // TODO: reject?
                    }
                    println!("{} {}", lv, idk3);

                    // oh god oh fuck
                    let header = [0xFFu8; 4];
                    let code = [74u8; 1];
                    let mapname = b"mp_lobby\0";
                    let gamemode = b"private_match\0";
                    let msg = [
                        header.as_ref(), // connectionless
                        &code, // 'J'
                        // ---
                        mapname.as_ref(),
                        gamemode.as_ref(),
                    ].concat();
                    println!("{:02X?}", msg);
                    
                    let nonce = Nonce::from_slice(&buf[..12]);
                    let enc = cipher.encrypt(nonce, Payload {
                        msg: &msg,
                        aad: aad,
                    }).expect("Enc error!");
                    println!("{:02X?}", enc);

                    let msg = [&buf[..12], &enc[enc.len()-16..], &enc[..enc.len()-16]].concat();
                    println!("{:02X?}", msg);
                    socket.send_to(&msg, src).expect("Data send failure lmfao");
                }
            }
        }
        else {
            // Oh god oh fuck...
            let bitbuf = BitReadBuffer::new(&plaintext, LittleEndian);
            let mut stream = BitReadStream::new(bitbuf);

            let in_seq: u32 = stream.read_int(32).unwrap();
            let out_seq: u32 = stream.read_int(32).unwrap();
            let flags: u8 = stream.read_int(8).unwrap();
            println!("{} {} | {}", in_seq, out_seq, flags);

            if flags&0x10 != 0 {
                let idk: u8 = stream.read_int(8).unwrap();
                println!("flags&0x10 {}", idk);
            }
            if flags&0x20 != 0 {
                println!("flags&0x20");
                continue;
            }
            if flags&0x40 != 0 {
                println!("flags&0x40");
                continue;
            }
            if flags&1 != 0 {
                println!("flags&1 - Reliable");
            } else {
                println!("UNRELIABLE DJSPAODJPASPDASPOFJPASJP");
                //continue; // ???
            }

            let idk: u32 = stream.read_int(9).unwrap();
            let unk = stream.read_bool().unwrap();
            //let unk2 = stream.read_bool().unwrap();
            println!("{} {}", idk, unk);
            if unk {
                println!("UNK IHDPASHDNOAS");
                continue;
            }

            /*if flags&1 == 0 {
                //let input = stream.read_bytes(stream.bits_left()/8).unwrap().to_vec();
                //parse(&socket, &src, &input, in_seq, out_seq, 0);
                let id: u32 = stream.read_int(6).unwrap();
                match id {
                    1 => {
                        // disconnect
                        if stream.bits_left() > 8 {
                            println!("{}", stream.read_string(None).unwrap());
                        }
                        println!("NET_Disconnect");
                    }
                    _ => {
                        println!("Unk unreliable {}", id);
                    }
                }

                continue;
            }*/

            if flags&1 != 0 {
                let mut brih: u32 = 0;

                let v6: u8 = stream.read_int(8).unwrap();
                println!("v6: {}", v6);
                if v6 == 0 {
                    let unk = stream.read_bool().unwrap();
                    if unk {
                        let idk: u32 = stream.read_int(32).unwrap();
                        brih = idk;
                        println!("\t{} {}", unk, idk);
                    } else {
                        println!("\t{} - unk", unk);
                    }

                    // everything up to this point is correct

                    for i in 0..255 {
                        if i != 0 {
                            let b = stream.read_bool().unwrap();
                            if !b {
                                break;
                            }
                        }
                        let mut size: u32 = 0;
                        let mut uncompressed_size: u32 = 0;
                        // single or multiple???
                        let b = stream.read_bool().unwrap(); // 0x131
                        if b {
                            // data of unk IS correct...
                            let unk: u32 = stream.read_int(18).unwrap(); // size!
                            size = unk;
                            let b = stream.read_bool().unwrap(); // 0x124 | compressed?
                            println!("\t SingleBlock {} compressed: {}", unk, b);
                            if b {
                                let unk: u32 = stream.read_int(21).unwrap(); // decompressed size!
                                uncompressed_size = unk;
                                println!("\t\t{}", unk);
                            }
                        } else {
                            let b = stream.read_bool().unwrap(); // 0x132
                            println!("\t MutliBlock {}", b);
                            if b {
                                let unk: u32 = stream.read_int(10).unwrap();
                                println!("\t\t{}", unk);
                            }
                        }

                        if size != 0 {
                            let bytes = stream.read_bytes(size as usize).unwrap();
                            //println!("\t{} {:02X?}", i, bytes);
                            if uncompressed_size != 0 {
                                let bitbuf = BitReadBuffer::new(&bytes, LittleEndian);
                                let mut stream = BitReadStream::new(bitbuf);
                                let id: u32 = stream.read_int::<u32>(32).unwrap();
                                if id == 0x53_53_5A_4C { //0x53_53_5A_4C {
                                    let uncompressed_size: u32 = stream.read_int::<u32>(32).unwrap();
                                    println!("Decomp: {}", uncompressed_size);
                                    //let mut buf: Vec<u8> = Vec::with_capacity(uncompressed_size as usize);
                                    let mut buf: Vec<u8> = Vec::new();

                                    decode(&bytes[8..], &mut buf).expect("Brih unpack");

                                    //println!("\t{} {:02X?} {}", i, buf, buf.len());
                                    parse(&socket, &src, &buf, in_seq, out_seq, brih);
                                } else {
                                    println!("Comp: {}", id);
                                }
                            } else {
                                parse(&socket, &src, &bytes.to_vec(), in_seq, out_seq, brih);
                            }
                        }
                    }
                } else {
                    continue;
                }
            }

            if flags&1 != 0 {
                continue; // also contains recv lists and shit...
            }

            /*if flags != 0 {
                println!("{} != 0", flags);
                continue;
            }*/

            loop {
                if stream.bits_left() < 6 {
                    break;
                }
                let id: u32 = stream.read_int(6).unwrap();
                match id {
                    0 => {
                        continue;
                    }
                    1 => {
                        // disconnect
                        if stream.bits_left() > 8 {
                            println!("{}", stream.read_string(None).unwrap());
                        }
                        println!("NET_Disconnect");
                    }
                    4 => {
                        // string cmd
                        let cmd = stream.read_string(None).unwrap();
                        println!("CMD {}", cmd);
                    }
                    7 => {
                        //svc_UserMessage
                        let id: u8 = stream.read_int(8).unwrap();
                        let size: usize = stream.read_int(12).unwrap();
                        let buf = stream.read_bits(size).unwrap();
        
                        println!("svc_UserMessage {} {}", id, size);
                    }
                    41 => {
                        //svc_GetCvarValue
                        let cookie: u32 = stream.read_int(32).unwrap();
                        let cvar = stream.read_string(None).unwrap();
                        println!("svc_GetCvarValue {} '{}'", cookie, cvar);
                    }
                    56 => {
                        // clc_SplitPlayerConnect
                        let count: u8 = stream.read_int(8).unwrap();
                        println!("clc_SplitPlayerConnect {}", count);
                        for _ in 0..count {
                            let key = stream.read_string(None).unwrap();
                            let val = stream.read_string(None).unwrap();
                            println!("\t'{}' '{}'", key, val);
                        }
                    }
                    _ => {
                        println!("Unk unreliable {}", id);
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}
