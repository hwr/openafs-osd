/*
 * Copyright (c) 1995 - 2000 Kungliga Tekniska H�gskolan
 * (Royal Institute of Technology, Stockholm, Sweden).
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>


#include <err.h>

#ifndef MAP_FAILED
#define MAP_FAILED ((void *)-1)
#endif

static char long_buf[] =
    "1000\n" "1001\n" "1002\n" "1003\n" "1004\n" "1005\n" "1006\n" "1007\n"
    "1008\n" "1009\n" "1010\n" "1011\n" "1012\n" "1013\n" "1014\n" "1015\n"
    "1016\n" "1017\n" "1018\n" "1019\n" "1020\n" "1021\n" "1022\n" "1023\n"
    "1024\n" "1025\n" "1026\n" "1027\n" "1028\n" "1029\n" "1030\n" "1031\n"
    "1032\n" "1033\n" "1034\n" "1035\n" "1036\n" "1037\n" "1038\n" "1039\n"
    "1040\n" "1041\n" "1042\n" "1043\n" "1044\n" "1045\n" "1046\n" "1047\n"
    "1048\n" "1049\n" "1050\n" "1051\n" "1052\n" "1053\n" "1054\n" "1055\n"
    "1056\n" "1057\n" "1058\n" "1059\n" "1060\n" "1061\n" "1062\n" "1063\n"
    "1064\n" "1065\n" "1066\n" "1067\n" "1068\n" "1069\n" "1070\n" "1071\n"
    "1072\n" "1073\n" "1074\n" "1075\n" "1076\n" "1077\n" "1078\n" "1079\n"
    "1080\n" "1081\n" "1082\n" "1083\n" "1084\n" "1085\n" "1086\n" "1087\n"
    "1088\n" "1089\n" "1090\n" "1091\n" "1092\n" "1093\n" "1094\n" "1095\n"
    "1096\n" "1097\n" "1098\n" "1099\n" "1100\n" "1101\n" "1102\n" "1103\n"
    "1104\n" "1105\n" "1106\n" "1107\n" "1108\n" "1109\n" "1110\n" "1111\n"
    "1112\n" "1113\n" "1114\n" "1115\n" "1116\n" "1117\n" "1118\n" "1119\n"
    "1120\n" "1121\n" "1122\n" "1123\n" "1124\n" "1125\n" "1126\n" "1127\n"
    "1128\n" "1129\n" "1130\n" "1131\n" "1132\n" "1133\n" "1134\n" "1135\n"
    "1136\n" "1137\n" "1138\n" "1139\n" "1140\n" "1141\n" "1142\n" "1143\n"
    "1144\n" "1145\n" "1146\n" "1147\n" "1148\n" "1149\n" "1150\n" "1151\n"
    "1152\n" "1153\n" "1154\n" "1155\n" "1156\n" "1157\n" "1158\n" "1159\n"
    "1160\n" "1161\n" "1162\n" "1163\n" "1164\n" "1165\n" "1166\n" "1167\n"
    "1168\n" "1169\n" "1170\n" "1171\n" "1172\n" "1173\n" "1174\n" "1175\n"
    "1176\n" "1177\n" "1178\n" "1179\n" "1180\n" "1181\n" "1182\n" "1183\n"
    "1184\n" "1185\n" "1186\n" "1187\n" "1188\n" "1189\n" "1190\n" "1191\n"
    "1192\n" "1193\n" "1194\n" "1195\n" "1196\n" "1197\n" "1198\n" "1199\n"
    "1200\n" "1201\n" "1202\n" "1203\n" "1204\n" "1205\n" "1206\n" "1207\n"
    "1208\n" "1209\n" "1210\n" "1211\n" "1212\n" "1213\n" "1214\n" "1215\n"
    "1216\n" "1217\n" "1218\n" "1219\n" "1220\n" "1221\n" "1222\n" "1223\n"
    "1224\n" "1225\n" "1226\n" "1227\n" "1228\n" "1229\n" "1230\n" "1231\n"
    "1232\n" "1233\n" "1234\n" "1235\n" "1236\n" "1237\n" "1238\n" "1239\n"
    "1240\n" "1241\n" "1242\n" "1243\n" "1244\n" "1245\n" "1246\n" "1247\n"
    "1248\n" "1249\n" "1250\n" "1251\n" "1252\n" "1253\n" "1254\n" "1255\n"
    "1256\n" "1257\n" "1258\n" "1259\n" "1260\n" "1261\n" "1262\n" "1263\n"
    "1264\n" "1265\n" "1266\n" "1267\n" "1268\n" "1269\n" "1270\n" "1271\n"
    "1272\n" "1273\n" "1274\n" "1275\n" "1276\n" "1277\n" "1278\n" "1279\n"
    "1280\n" "1281\n" "1282\n" "1283\n" "1284\n" "1285\n" "1286\n" "1287\n"
    "1288\n" "1289\n" "1290\n" "1291\n" "1292\n" "1293\n" "1294\n" "1295\n"
    "1296\n" "1297\n" "1298\n" "1299\n" "1300\n" "1301\n" "1302\n" "1303\n"
    "1304\n" "1305\n" "1306\n" "1307\n" "1308\n" "1309\n" "1310\n" "1311\n"
    "1312\n" "1313\n" "1314\n" "1315\n" "1316\n" "1317\n" "1318\n" "1319\n"
    "1320\n" "1321\n" "1322\n" "1323\n" "1324\n" "1325\n" "1326\n" "1327\n"
    "1328\n" "1329\n" "1330\n" "1331\n" "1332\n" "1333\n" "1334\n" "1335\n"
    "1336\n" "1337\n" "1338\n" "1339\n" "1340\n" "1341\n" "1342\n" "1343\n"
    "1344\n" "1345\n" "1346\n" "1347\n" "1348\n" "1349\n" "1350\n" "1351\n"
    "1352\n" "1353\n" "1354\n" "1355\n" "1356\n" "1357\n" "1358\n" "1359\n"
    "1360\n" "1361\n" "1362\n" "1363\n" "1364\n" "1365\n" "1366\n" "1367\n"
    "1368\n" "1369\n" "1370\n" "1371\n" "1372\n" "1373\n" "1374\n" "1375\n"
    "1376\n" "1377\n" "1378\n" "1379\n" "1380\n" "1381\n" "1382\n" "1383\n"
    "1384\n" "1385\n" "1386\n" "1387\n" "1388\n" "1389\n" "1390\n" "1391\n"
    "1392\n" "1393\n" "1394\n" "1395\n" "1396\n" "1397\n" "1398\n" "1399\n"
    "1400\n" "1401\n" "1402\n" "1403\n" "1404\n" "1405\n" "1406\n" "1407\n"
    "1408\n" "1409\n" "1410\n" "1411\n" "1412\n" "1413\n" "1414\n" "1415\n"
    "1416\n" "1417\n" "1418\n" "1419\n" "1420\n" "1421\n" "1422\n" "1423\n"
    "1424\n" "1425\n" "1426\n" "1427\n" "1428\n" "1429\n" "1430\n" "1431\n"
    "1432\n" "1433\n" "1434\n" "1435\n" "1436\n" "1437\n" "1438\n" "1439\n"
    "1440\n" "1441\n" "1442\n" "1443\n" "1444\n" "1445\n" "1446\n" "1447\n"
    "1448\n" "1449\n" "1450\n" "1451\n" "1452\n" "1453\n" "1454\n" "1455\n"
    "1456\n" "1457\n" "1458\n" "1459\n" "1460\n" "1461\n" "1462\n" "1463\n"
    "1464\n" "1465\n" "1466\n" "1467\n" "1468\n" "1469\n" "1470\n" "1471\n"
    "1472\n" "1473\n" "1474\n" "1475\n" "1476\n" "1477\n" "1478\n" "1479\n"
    "1480\n" "1481\n" "1482\n" "1483\n" "1484\n" "1485\n" "1486\n" "1487\n"
    "1488\n" "1489\n" "1490\n" "1491\n" "1492\n" "1493\n" "1494\n" "1495\n"
    "1496\n" "1497\n" "1498\n" "1499\n" "1500\n" "1501\n" "1502\n" "1503\n"
    "1504\n" "1505\n" "1506\n" "1507\n" "1508\n" "1509\n" "1510\n" "1511\n"
    "1512\n" "1513\n" "1514\n" "1515\n" "1516\n" "1517\n" "1518\n" "1519\n"
    "1520\n" "1521\n" "1522\n" "1523\n" "1524\n" "1525\n" "1526\n" "1527\n"
    "1528\n" "1529\n" "1530\n" "1531\n" "1532\n" "1533\n" "1534\n" "1535\n"
    "1536\n" "1537\n" "1538\n" "1539\n" "1540\n" "1541\n" "1542\n" "1543\n"
    "1544\n" "1545\n" "1546\n" "1547\n" "1548\n" "1549\n" "1550\n" "1551\n"
    "1552\n" "1553\n" "1554\n" "1555\n" "1556\n" "1557\n" "1558\n" "1559\n"
    "1560\n" "1561\n" "1562\n" "1563\n" "1564\n" "1565\n" "1566\n" "1567\n"
    "1568\n" "1569\n" "1570\n" "1571\n" "1572\n" "1573\n" "1574\n" "1575\n"
    "1576\n" "1577\n" "1578\n" "1579\n" "1580\n" "1581\n" "1582\n" "1583\n"
    "1584\n" "1585\n" "1586\n" "1587\n" "1588\n" "1589\n" "1590\n" "1591\n"
    "1592\n" "1593\n" "1594\n" "1595\n" "1596\n" "1597\n" "1598\n" "1599\n"
    "1600\n" "1601\n" "1602\n" "1603\n" "1604\n" "1605\n" "1606\n" "1607\n"
    "1608\n" "1609\n" "1610\n" "1611\n" "1612\n" "1613\n" "1614\n" "1615\n"
    "1616\n" "1617\n" "1618\n" "1619\n" "1620\n" "1621\n" "1622\n" "1623\n"
    "1624\n" "1625\n" "1626\n" "1627\n" "1628\n" "1629\n" "1630\n" "1631\n"
    "1632\n" "1633\n" "1634\n" "1635\n" "1636\n" "1637\n" "1638\n" "1639\n"
    "1640\n" "1641\n" "1642\n" "1643\n" "1644\n" "1645\n" "1646\n" "1647\n"
    "1648\n" "1649\n" "1650\n" "1651\n" "1652\n" "1653\n" "1654\n" "1655\n"
    "1656\n" "1657\n" "1658\n" "1659\n" "1660\n" "1661\n" "1662\n" "1663\n"
    "1664\n" "1665\n" "1666\n" "1667\n" "1668\n" "1669\n" "1670\n" "1671\n"
    "1672\n" "1673\n" "1674\n" "1675\n" "1676\n" "1677\n" "1678\n" "1679\n"
    "1680\n" "1681\n" "1682\n" "1683\n" "1684\n" "1685\n" "1686\n" "1687\n"
    "1688\n" "1689\n" "1690\n" "1691\n" "1692\n" "1693\n" "1694\n" "1695\n"
    "1696\n" "1697\n" "1698\n" "1699\n" "1700\n" "1701\n" "1702\n" "1703\n"
    "1704\n" "1705\n" "1706\n" "1707\n" "1708\n" "1709\n" "1710\n" "1711\n"
    "1712\n" "1713\n" "1714\n" "1715\n" "1716\n" "1717\n" "1718\n" "1719\n"
    "1720\n" "1721\n" "1722\n" "1723\n" "1724\n" "1725\n" "1726\n" "1727\n"
    "1728\n" "1729\n" "1730\n" "1731\n" "1732\n" "1733\n" "1734\n" "1735\n"
    "1736\n" "1737\n" "1738\n" "1739\n" "1740\n" "1741\n" "1742\n" "1743\n"
    "1744\n" "1745\n" "1746\n" "1747\n" "1748\n" "1749\n" "1750\n" "1751\n"
    "1752\n" "1753\n" "1754\n" "1755\n" "1756\n" "1757\n" "1758\n" "1759\n"
    "1760\n" "1761\n" "1762\n" "1763\n" "1764\n" "1765\n" "1766\n" "1767\n"
    "1768\n" "1769\n" "1770\n" "1771\n" "1772\n" "1773\n" "1774\n" "1775\n"
    "1776\n" "1777\n" "1778\n" "1779\n" "1780\n" "1781\n" "1782\n" "1783\n"
    "1784\n" "1785\n" "1786\n" "1787\n" "1788\n" "1789\n" "1790\n" "1791\n"
    "1792\n" "1793\n" "1794\n" "1795\n" "1796\n" "1797\n" "1798\n" "1799\n"
    "1800\n" "1801\n" "1802\n" "1803\n" "1804\n" "1805\n" "1806\n" "1807\n"
    "1808\n" "1809\n" "1810\n" "1811\n" "1812\n" "1813\n" "1814\n" "1815\n"
    "1816\n" "1817\n" "1818\n" "1819\n" "1820\n" "1821\n" "1822\n" "1823\n"
    "1824\n" "1825\n" "1826\n";

/*
 * compare this file with read and mmap.
 * return 0 iff identical.
 */

static int
compare_file(const char *filename)
{
    struct stat sb;
    int fd;
    int ret;
    void *read_buf;
    void *mmap_buf;

    fd = open(filename, O_RDONLY);
    if (fd < 0)
	err(1, "open %s", filename);
    ret = fstat(fd, &sb);
    if (ret < 0)
	err(1, "stat %s", filename);
    read_buf = malloc(sb.st_size);
    if (read_buf == NULL)
	err(1, "malloc %u", (unsigned)sb.st_size);
    ret = read(fd, read_buf, sb.st_size);
    if (ret < 0)
	err(1, "read %s", filename);
    if (ret != sb.st_size)
	errx(1, "short read from %s", filename);
    mmap_buf = mmap(NULL, sb.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (mmap_buf == (void *)MAP_FAILED)
	err(1, "mmap %s", filename);
    ret = memcmp(read_buf, mmap_buf, sb.st_size);
    close(fd);
    free(read_buf);
    return ret;
}

static void
doit(const char *filename)
{
    int fd;
    int ret;

    fd = open(filename, O_WRONLY | O_APPEND | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
	err(1, "open %s", filename);
    ret = close(fd);
    if (ret < 0)
	err(1, "close %s", filename);
    fd = open(filename, O_WRONLY | O_APPEND);
    if (fd < 0)
	err(1, "open %s", filename);
    ret = write(fd, "foobar\n", 7);
    if (ret < 0)
	err(1, "write %s", filename);
    if (ret != 7)
	errx(1, "short write to %s", filename);
    ret = close(fd);
    if (ret < 0)
	err(1, "close %s", filename);

    if (compare_file(filename))
	errx(1, "compare 1 failed");

    fd = open(filename, O_WRONLY | O_APPEND);
    if (fd < 0)
	err(1, "open %s", filename);
    ret = write(fd, long_buf, strlen(long_buf));
    if (ret < 0)
	err(1, "write %s", filename);
    if (ret != strlen(long_buf))
	errx(1, "short write to %s", filename);
    ret = close(fd);
    if (ret < 0)
	err(1, "close %s", filename);

    if (compare_file(filename))
	errx(1, "compare 2 failed");
}

int
main(int argc, char **argv)
{
    const char *file = "blaha";

    if (argc != 1 && argc != 2)
	errx(1, "usage: %s [file]", argv[0]);
    if (argc == 2)
	file = argv[1];
    doit(file);
    return 0;
}
