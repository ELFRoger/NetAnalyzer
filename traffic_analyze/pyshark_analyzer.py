import pyshark


class wireshark_analysis_script():

    # 此函数的作用是封装一下pyshark.FileCapture
    def read_packets_from_file(self, packets_file_path, tshark_path, display_filter):
        packets_file_obj = pyshark.FileCapture(input_file=packets_file_path, tshark_path=tshark_path, display_filter=display_filter)
        return packets_file_obj

    # 此函数的作用是从传送过来的所有数据包中，抽取并返回{ip_server,ip_client,port_server,port_client}四元组
    def get_target_client_ip_port(self, packets_file_obj):
        for tmp_packet in packets_file_obj:
            ip_server = tmp_packet.ip.src
            port_server = tmp_packet.tcp.srcport
            ip_client = tmp_packet.ip.dst
            port_client = tmp_packet.tcp.dstport
            stream_value = tmp_packet.tcp.stream
            yield {"ip_server": ip_server, "port_server": port_server, "ip_client": ip_client, "port_client": port_client,"stream_value":stream_value}

    # 此函数的作用是读取传过来的所有数据包应用层的数据，并打印
    def follow_tcp_stream(self, packets_file_obj, ip, port):
        for tmp_packet in packets_file_obj:
            highest_layer_name = tmp_packet.highest_layer
            #追踪流时会有握手挥手tcp将其排除
            if highest_layer_name != "TCP":
                if ((tmp_packet.ip.dst == ip) and (tmp_packet.tcp.dstport == port)):
                    print("server(%s:%s)->client(%s:%s): %s" % (tmp_packet.ip.src, tmp_packet.tcp.srcport, tmp_packet.ip.dst, tmp_packet.tcp.dstport, tmp_packet[highest_layer_name].get_field('data')))
                elif ((tmp_packet.ip.src == ip) and (tmp_packet.tcp.srcport == port)):
                    print("client(%s:%s)->server(%s:%s): %s" % (tmp_packet.ip.src, tmp_packet.tcp.srcport, tmp_packet.ip.dst, tmp_packet.tcp.dstport, tmp_packet[highest_layer_name].get_field('data')))


if __name__ == '__main__':
    # 要读取的wireshark数据包的所在的路径
    packets_file_path = '../http_00000_20190529155900.pcap'
    # tshark程序所在的路径，tshark随wireshark安装
    tshark_path = 'C:\\Program Files\\Wireshark\\tshark.exe'
    # 过滤器表达式，与在wireshark中使用时的写法完全相同
    first_step_filter = 'http'
    # 用于存放要追踪流的ip和端口
    target_client_ip_port = []

    # 实例化类
    wireshark_analysis_script_instance = wireshark_analysis_script()
    # 使用first_step_filter过滤器表达式，过滤出要追踪流的数据包
    first_step_obj = wireshark_analysis_script_instance.read_packets_from_file(packets_file_path, tshark_path, first_step_filter)
    # 从要追踪流的数据包中抽取出ip和端口
    target_client_ip_port = wireshark_analysis_script_instance.get_target_client_ip_port(first_step_obj)
    first_step_obj.close()
    # 遍历要追踪流的ip+端口组合
    for target_client_ip_port_temp in target_client_ip_port:
        # stream的值
        stream_value = target_client_ip_port_temp['stream_value']
        ip_client = target_client_ip_port_temp['ip_client']
        port_client = target_client_ip_port_temp['port_client']
        # tcp.stream eq 70形式。为了排除tcp其实可以再直接加上and telnet
        second_step_filter = 'tcp.stream eq %s' % (stream_value)
        second_step_obj = wireshark_analysis_script_instance.read_packets_from_file(packets_file_path, tshark_path, second_step_filter)
        print("[%s:%s]" % (ip_client, port_client))
        # 调用follow_tcp_stream将认为是同一个流的所有数据包的应用层数据打印
        wireshark_analysis_script_instance.follow_tcp_stream(second_step_obj, ip_client, port_client)
        second_step_obj.close()