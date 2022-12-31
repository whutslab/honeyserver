from fingerprint_modify import Fingerprint
import pymongo
import socket


# def get_fingerprints_experiments(cur, min_nb_fingerprints, attributes):
#     """
#         Returns a list of the fingerprints to use for the experiment 返回已知类别的指纹列表
#     """
#     cur.execute("SELECT * FROM extensionDataScheme")
#     fps = cur.fetchall()
#     # myclient = pymongo.MongoClient("mongodb://10.211.55.4:27017/")
#     # mydb = myclient["agent"]
#     # mycol = mydb["fp_experiments"]
#     fp_set = []
#     for fp in fps:
#         #mycol.insert(fp)
#         try:
#             fp_set.append(Fingerprint(attributes, fp))#属性赋值
#         except Exception as e:
#             print(e)
#     #print("know:",len(fp_set))
#     return fp_set
#
# def get_unknown_fingerprint(cur, attributes):
#     """
#         返回未知指纹
#     """
#     cur.execute("SELECT * FROM unknowFP")
#     fps = cur.fetchall()
#     fp_set = []
#     for fp in fps:
#         try:
#             fp_set.append(Fingerprint(attributes, fp))#属性赋值
#         except Exception as e:
#             print(e)
#     #print(fp_set.len)
# #指定未知指纹样本
#     return fp_set[0]

def get_unkonwn_fp(attributes):
    url = "mongodb://192.168.137.65:27017/"
    myclient = pymongo.MongoClient(url)
    mydb = myclient["agent"]
    mycol = mydb["fpinfo"]
    fps_all = mycol.find({}, {"hardwareconcurrency":0,"timezone":0,"localip":0}).sort("creationDate",-1)
    fps = next(fps_all)
    try:
        res = Fingerprint.unknownfp(attributes, fps)
        #print(res)
    except Exception as e:
            print(e)
    return res

def get_fp_experiments(min_nb_fingerprints, attributes):
    #url = "mongodb://"+get_host_ip()+":27017/"
    url = "mongodb://192.168.137.65:27017/"
    myclient = pymongo.MongoClient(url)
    mydb = myclient["agent"]
    mycol = mydb["FpLibrary"]
    fps = tuple(mycol.find({}, {"hardwareconcurrency":0,"timezone":0,"localip":0}))
    fp_set = []
    for fp in fps:
        try:
            fp_set.append(Fingerprint.unknownfp(attributes, fp))  # 属性赋值
        except Exception as e:
            print(e)
    return fp_set

def get_host_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip
