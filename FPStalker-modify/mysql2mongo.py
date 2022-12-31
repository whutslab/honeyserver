import MySQLdb as mdb
import pymongo

def contoDB():
    con = mdb.connect('localhost', 'root', 'whuc401', 'canvas_fp_projects')
    cur_mysql = con.cursor(mdb.cursors.DictCursor)

    myclient = pymongo.MongoClient("mongodb://10.211.55.4:27017/")
    mydb = myclient["agent"]
    mycol_mongo = mydb["FpLibrary"]

    cur_mysql.execute("SELECT counter,id,creationDate,userAgentHttp,fontsFlash,languageHttp,pluginsJS,platformJS,cookiesJS,dntJS,resolutionJS,rendererWebGLJS,canvasJSHashed FROM extensionDataScheme")
    fps = list(cur_mysql.fetchall())
    for fp in fps:
        fp['localip']=''
        fp['hardwareconcurrency'] = ''
        fp['timezone'] = ''
        mycol_mongo.insert_one(fp)

def main():
    contoDB()

if __name__ == "__main__":
    main()