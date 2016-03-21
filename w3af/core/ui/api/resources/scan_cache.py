import threading
lock = threading.Lock()

scan_cache = dict()
scan_Id2Url = dict()
class CacheItem:
	scanId = 0
	scanResult = None

def scanExist(url):
	try:
		lock.acquire()
		if url in scan_cache:
			return True
	finally:
		lock.release()
	return False

def scanAddItem(scanId, item):
	try:
		lock.acquire()
		scanUrl = scan_Id2Url[scanId]
		if scanUrl != None:
			cacheItem = CacheItem()
			cacheItem.scanId = scanId
			scanResult = item
			scan_cache[scanUrl] = scanResult
	finally:
		lock.release()

def scanAddId(scanId, scanUrl):
	try:
		lock.acquire()
		scan_Id2Url[scanId] = scanUrl
		item = CacheItem()
		item.scanId = scanId
		scan_cache[scanUrl] = item
	finally:
		lock.release()

def scanGetWithScanId(scanId):
	try:
		lock.acquire()
		if not scanId in scan_Id2Url:
			return None
		return scan_cache[scan_Id2Url[scanId]]
	finally:
		lock.release()

def scanGetUrl(scanId):
	try:
		lock.acquire()
		if not scanId in scan_Id2Url:
			return None
		return scan_Id2Url[scanId]
	finally:
		lock.release()


def scanGet(scanUrl):
	try:
		lock.acquire()
		if not scanUrl in scan_cache:
			return None
		return scan_cache[scanUrl]
	finally:
		lock.release()


def scanDelete(scanUrl):
	try:
		lock.acquire()
		scanId = None
		if scanUrl in scan_cache:
			scanId = scan_cache[scanUrl].scanId
			del scan_cache[scanUrl]
		if scanId != None and  scanId in scan_Id2Url:
			del scan_Id2Url[scanId]
	finally:
		lock.release()
	

