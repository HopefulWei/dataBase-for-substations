# coding: utf-8
import struct
string_data = []
fpcap = open("/Users/hopefulguowei/PycharmProjects/database/undo/attack/demoSV8.pcap", 'rb')  # 读协议数据包
string_data = fpcap.read()[24:] #把协议每一个byte当做一个list元素放进一个list中
from matplotlib import pyplot as plt
i = 0   #大包头数据24byte
A=[[]for k in range(6)]
while (i < len(string_data)):
    packet_len = struct.unpack('<I', string_data[i + 12:i + 16])[0]
    IA = 0
    IB = 0
    IC = 0
    VA = 0
    VB = 0
    VC = 0
    IA1 = struct.unpack('>I', string_data[i + 0xc6:i + 0xca])[0]
    IA = max(IA, IA1)
    IB1 = struct.unpack('>I', string_data[i + 0xce:i + 0xd2])[0]
    IB = max(IB, IB1)
    IC1 = struct.unpack('>I', string_data[i + 0xd6:i + 0xda])[0]
    IC = max(IC, IC1)
    VA1 = struct.unpack('>I', string_data[i + 0xde:i + 0xe2])[0]
    VA2 = struct.unpack('>I', string_data[i + 0xe6:i + 0xea])[0]
    VA = max(VA1, VA, VA2)
    VB1 = struct.unpack('>I', string_data[i + 0xee:i + 0xf2])[0]
    VB2 = struct.unpack('>I', string_data[i + 0xf6:i + 0xfa])[0]
    VB = max(VB, VB1, VB2)
    VC1 = struct.unpack('>I', string_data[i + 0xfe:i + 0x102])[0]
    VC2 = struct.unpack('>I', string_data[i + 0x106:i + 0x10a])[0]
    VC = max(VC, VC1, VC2)
    A[0].append(IA)
    A[1].append(IB)
    A[2].append(IC)
    A[3].append(VA)
    A[4].append(VB)
    A[5].append(VC)
    i=i+packet_len+16
B=['IA','IB','IC',"VA",'VB','VC']
for i in range(0,len(A)):
    x=[]
    for j in range(len(A[i])):
        x.append(j+1)
    y = A[i]
    plt.title('attack-breakA %s'%B[i])
    plt.ylabel('variable Y')
    plt.xlabel('Variable X')
    plt.scatter(x,y)
    plt.show()
