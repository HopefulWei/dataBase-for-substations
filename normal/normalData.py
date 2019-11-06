# coding: utf-8
import time
import struct  #引用对应模块
import pandas as pd
string_data = []
fpcap1 = open("/Users/hopefulguowei/PycharmProjects/database/undo/normal/normalGOOSE.pcap", 'rb')  # 读协议数据包
A=[[]for i in range(30)]
string_data = fpcap1.read()[24:] #把协议每一个byte当做一个list元素放进一个list中
i = 0   #大包头数据24byte
IT_STATE_TIME=0
IT_ALARM_TIME=0
LPD_TIME=0
j=0
while (i < len(string_data)):
    packet_len = struct.unpack('<I', string_data[i + 12:i + 16])[0]
    if(string_data[i+19]=='\x01' and string_data[i+21]=='\x1a'): # 智能终端状态数据包信息
        time1=struct.unpack('<I',string_data[i :i + 4])[0]
        timeArray2 = time.localtime(time1)
        print(time1)
        A[0].append(time1)
        print(A[0][-1])
        A[1].append(time1-IT_STATE_TIME)
        IT_STATE_TIME=time1
        A[2].append(struct.unpack('>I', string_data[i + 0x80:i + 0x84])[0])
        A[3].append(struct.unpack('>I', string_data[i + 0x8a:i + 0x8e])[0])
        A[4].append(struct.unpack('>I', string_data[i + 0x90:i + 0x94])[0])
        A[5].append(struct.unpack('B', string_data[i + 0x96])[0])
        A[6].append(1 if struct.unpack('B', string_data[i + 0xad])[0]==128 else 0)
        A[7].append(1 if struct.unpack('B', string_data[i + 0xbb])[0]==128 else 0)
        A[8].append(1 if struct.unpack('B', string_data[i + 0xc9])[0]==128 else 0)
        A[9].append(struct.unpack('B', string_data[i + 0x1a7])[0])
        A[10].append(struct.unpack('B', string_data[i + 0x1aa])[0])
        i = i + packet_len + 16
        while(i +0xb5< len(string_data)): #智能终端告警数据包信息
            j=j+1
            packet_len = struct.unpack('<I', string_data[i + 12:i + 16])[0]
            if (string_data[i+19] == '\x01' and string_data[i+21] == '\x18'):
                time1 = struct.unpack('<I', string_data[i:i + 4])[0]
                A[11].append(time1-IT_ALARM_TIME)
                IT_ALARM_TIME=time1
                A[12].append(struct.unpack('>I', string_data[i + 0x80:i + 0x84])[0])
                A[13].append(struct.unpack('>I', string_data[i + 0x8a:i + 0x8e])[0])
                A[14].append(struct.unpack('>I', string_data[i + 0x90:i + 0x94])[0])
                A[15].append(struct.unpack('B', string_data[i + 0xac])[0])
                A[16].append(struct.unpack('B', string_data[i + 0xaf])[0])
                A[17].append(struct.unpack('B', string_data[i + 0xb2])[0])
                A[18].append(struct.unpack('B', string_data[i + 0xb5])[0])
                break
            i = i + packet_len + 16
        i = i + packet_len + 16
        while (i +0xb1< len(string_data)): #线路指令数据包信息
            j=j+1
            packet_len = struct.unpack('<I', string_data[i + 12:i + 16])[0]
            if (string_data[i+19] == '\x01' and string_data[i+21] == '\x14'):
                time2 = struct.unpack('<I', string_data[i:i + 4])[0]
                A[19].append(time2 - LPD_TIME)
                LPD_TIME = time2
                A[20].append(struct.unpack('>I', string_data[i + 0x7f:i + 0x83])[0])
                A[21].append(struct.unpack('>I', string_data[i + 0x89:i + 0x8d])[0])
                A[22].append(struct.unpack('>I', string_data[i + 0x8f:i + 0x93])[0])
                A[23].append(struct.unpack('B', string_data[i + 0x95])[0])
                A[24].append(struct.unpack('>I', string_data[i + 0x98:i + 0x9c])[0])
                A[25].append(struct.unpack('B', string_data[i + 0xab])[0])
                A[26].append(struct.unpack('B', string_data[i + 0xae])[0])
                A[27].append(struct.unpack('B', string_data[i + 0xb1])[0])
                break
            i = i + packet_len + 16
        A[28].append(0)
        A[29].append(0)
    i = i + packet_len + 16
    j=j+1
min=100000
for num in range(len(A)): # 对齐
    if(len(A[num])<min):
        min=len(A[num])

for num in range(len(A)):
    while(len(A[num])>min):
        A[num].pop()

B=['ITS Timestamp', 'ITS time interval', 'ITS UTC', 'ITS stNum', 'ITS sqNum', 'ITS TEST', 'ITS BreakA', 'ITS BreakB', 'ITS BreakC', 'ITS Breaker TP Position',
   'ITS Blocking reclosing','ITA time interval', 'ITA UTC', 'ITA stNum', 'ITA sqNum','ITA Run Abnormal', 'ITA Device Abnormal', 'ITA synchronization exception','ITA Abnormal pressure','LPD time interval',
   'LPD UTC', 'LPD stNum', 'LPD sqNum', 'LPD TEST', 'LPD Blocking protection', 'LPD BreakA', 'LPD BreakB', 'LPD BreakC','Whether attacked','Type of attack']
dataframe = pd.DataFrame({B[0]:A[0],B[1]:A[1],B[2]:A[2],B[3]:A[3],B[4]:A[4],B[5]:A[5],B[6]:A[6],B[7]:A[7],B[8]:A[8],B[9]:A[9],B[10]:A[10],B[11]:A[11],B[12]:A[12],B[13]:A[13],B[14]:A[14],B[15]: A[15],
                          B[16]: A[16], B[17]: A[17], B[18]: A[18], B[19]: A[19],B[20]:A[20],B[21]:A[21],B[22]:A[22],B[23]:A[23],B[24]:A[24],B[25]: A[25], B[26]: A[26], B[27]: A[27],B[28]: A[28], B[29]: A[29]})
dataframe.to_csv("/Users/hopefulguowei/PycharmProjects/database/doneData/normal/n0GOOSE.csv",index=False,sep=',')