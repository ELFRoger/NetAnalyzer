/*
author :
id :
last_date : 2018-10-5
info : this is the initial database code, create database and table, and the TABLE_tutorials_tbl is not in use
 */

DROP database IF EXISTS net_analyzer;
create database net_analyzer CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;

use net_analyzer;

DROP table IF EXISTS HTTP_RAW_DATA;
create table HTTP_RAW_DATA(
    id INT PRIMARY KEY AUTO_INCREMENT,      # serial number for no use
    time varchar(100) NOT NULL,             # log the time
    src varchar(20) NOT NULL,               # log the source of this packet
    src_port varchar(20) NOT NULL,          # log the source port of this packet
    dst varchar(20) NOT NULL,               # log the destination of this packet
    dst_port varchar(20) NOT NULL,          # log the destination port of this packet
    http_type varchar(20) NOT NULL,         # request or response
    method varchar(20) NOT NULL,            # request method , GET POST etc.
    url TEXT NOT NULL,                      # log the url in request packet
    http_version varchar(20) NOT NULL,      # log the version of the http protocol
    status varchar(20) NOT NULL,            # log the return status, 200 404 etc.
    reason varchar(255) NOT NULL,           # log the reason of return status
    headers TEXT NOT NULL,                  # log the header of the packet
    body TEXT NOT NULL                      # log the inner body of the packet
)DEFAULT CHARSET=utf8mb4  COLLATE utf8mb4_general_ci;


DROP table IF EXISTS HTTP_REQUEST;
create table HTTP_REQUEST(
    id INT PRIMARY KEY AUTO_INCREMENT,      # serial number for no request
    time varchar(100) NOT NULL,             # log the time
    src varchar(20) NOT NULL,               # log the source of this packet
    src_port varchar(20) NOT NULL,          # log the source port of this packet
    method varchar(20) NOT NULL,            # request method , GET POST etc.
    url TEXT NOT NULL,                      # log the url in request packet
    http_version varchar(20) NOT NULL,      # log the version of the http protocol
    headers TEXT NOT NULL                   # log the header of the packet
)DEFAULT CHARSET=utf8mb4  COLLATE utf8mb4_general_ci;


DROP table IF EXISTS TCPIP_FINGERPRINT;
create table TCPIP_FINGERPRINT(
    id INT PRIMARY KEY AUTO_INCREMENT,      # serial number for no request
    time varchar(100) NOT NULL,             # log the time
    src varchar(20) NOT NULL,               # log the source of this packet
    src_port varchar(20) NOT NULL,          # log the source port of this packet
    syn_len varchar(20) NOT NULL,           # syn packet length
    win varchar(20) NOT NULL,               # log the win in syn packet
    ttl varchar(20) NOT NULL,               # log the ttl of syn packet
    df varchar(20) NOT NULL,                # log the df of syn packet
    rst varchar(20) NOT NULL,               # log the rst of syn packet
    mss varchar(20) NOT NULL,               # log the mss of syn packet
)DEFAULT CHARSET=utf8mb4  COLLATE utf8mb4_general_ci;




