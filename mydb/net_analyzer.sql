/*
author : 王宇
id : 4everdestiny
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
    reason varchar(100) NOT NULL,           # log the reason of return status
    headers TEXT NOT NULL,                  # log the header of the packet
    body TEXT NOT NULL                      # log the inner body of the packet
)DEFAULT CHARSET=utf8mb4  COLLATE utf8mb4_general_ci;

