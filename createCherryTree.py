import os
import sqlite3
import glob

reconDir="recon/"
databasename="documentation.ctb"
ipAddress=""

def createCherryTree(ipAddress, reconDir, databasename):

    # delete all empty files
    os.system('find . -maxdepth 1 -type f -size 0 -delete')


    # create root node with port scan results of all ports
    f = open(reconDir + "0_tcp_nmap.txt", "r")
    data=f.read().decode("UTF-8")
    f.close()
    conn = sqlite3.connect(databasename)
    c = conn.cursor()
    c.execute("DELETE FROM node;")
    c.execute("DELETE FROM children;")
    c.execute("""INSERT INTO node VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""" , ('1', ipAddress, data, 'plain-text', '', '0', '1', '0', '0', '0', '0', '1591875124.22801', '1591875124.22801'))
    c.execute("INSERT INTO children VALUES(1, 0, 1);")
    conn.commit()


    # create sub nodes with port scan results of each ports
    for filename in glob.glob(reconDir + "*nmap*.txt"):
        f = open(filename, "r")
        data=f.read().decode("UTF-8")
        f.close()
        filename = filename.replace(reconDir, "")
        port = filename.split('_')[0]
        toolname = filename.split('_')[1] + "_" + filename.split('_')[2]
        if port == '0':
            continue
        # create node with port
        c.execute("""INSERT INTO node VALUES((select max(node_id) from node) + 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""" , (port, '', 'plain-text', '', '0', '1', '0', '0', '0', '0', '1591875124.22801', '1591875124.22801'))
        c.execute("INSERT INTO children VALUES((select max(node_id) from children) + 1, 1, (select max(sequence) from children) + 1);")
    
        # create subnode enum
        c.execute("""INSERT INTO node VALUES((select max(node_id) from node) + 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""" , ('enum', '', 'plain-text', '', '0', '1', '0', '0', '0', '0', '1591875124.22801', '1591875124.22801'))
        c.execute("INSERT INTO children VALUES((select max(node_id) from children) + 1, (select max(node_id) from node) - 1, 1);")
        enum_id = c.execute("select max(node_id) from node;").fetchone()[0]
    
    
        # create subnode of enum
        c.execute("""INSERT INTO node VALUES((select max(node_id) from node) + 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""" , (toolname, data, 'plain-text', '', '0', '1', '0', '0', '0', '0', '1591875124.22801', '1591875124.22801'))
        c.execute("INSERT INTO children VALUES((select max(node_id) from children) + 1, " + str(enum_id) + ", 1);")

        # attach other scan results
        for filename in glob.glob(reconDir + "*" + port + "*.txt"):
            if "nmap" in filename:
                continue
            # open file and read its contents
            f = open(filename, "r")
            data=f.read().decode("UTF-8")
            f.close()
            toolname = filename.split('_')[1] + "_" + filename.split('_')[2]

            # create subnode of enum
            c.execute("""INSERT INTO node VALUES((select max(node_id) from node) + 1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);""" , (toolname, data, 'plain-text', '', '0', '1', '0', '0', '0', '0', '1591875124.22801', '1591875124.22801'))
            c.execute("INSERT INTO children VALUES((select max(node_id) from children) + 1, " + str(enum_id) + ", 1);")

        conn.commit()
