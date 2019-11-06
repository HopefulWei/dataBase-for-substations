# coding: utf-8
import struct  #引用对应模块
import pandas as pd
import csv
string_data = []
fpcap3 = open("/Users/hopefulguowei/PycharmProjects/database/undo/attack/demoSV2.pcap", 'rb')  # 读协议数据包
string_data = fpcap3.read()[24:] #把协议每一个byte当做一个list元素放进一个list中
i = 0   #大包头数据24byte
IT_STATE_TIME=0
SV_TIME=0
A=[[]for k in range(6)]
j=0;
while(i+16<len(string_data)):
    packet_len = struct.unpack('<I', string_data[i + 12:i + 16])[0]
    i=i+16+packet_len

i=i-16-packet_len

def load(i):
    #print(i)
    IA=0;IB=0;IC=0;VA=0;VB=0;VC=0
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
with open('/Users/hopefulguowei/PycharmProjects/database/doneData/attack/02GOOSE.csv',"r")as csvfile:
    reader = csv.reader(csvfile)
    k=0
    for row in reader:
        if(k==0):
            k=k+1
            continue
        a=int(row[14])
        time1 = struct.unpack('<I', string_data[i:i + 4])[0]
        packet_len = struct.unpack('<I', string_data[i + 12:i + 16])[0]
        if(a-time1<-1):
            continue
        elif(-1<=a-time1 and a-time1<1):
            load(i)
            i = i - packet_len - 16
        elif(a-time1>1):
            print(i,i - packet_len - 16)
            while(a-time1>1 and (i - packet_len - 16)>0):
                i = i - packet_len - 16
                packet_len = struct.unpack('<I', string_data[i + 12:i + 16])[0]
                time1 = struct.unpack('<I', string_data[i:i + 4])[0]
            load(i)

        print('a',a)
        print('time',time1)

dataframe = pd.DataFrame({'IA':A[0],'IB':A[1],'IC':A[2],'VA':A[3],'VB':A[4],'VC':A[5]})
dataframe.to_csv("/Users/hopefulguowei/PycharmProjects/database/doneData/attack/02SV.csv",index=False,sep=',')


