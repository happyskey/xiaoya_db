#!/usr/bin/env python3
import argparse
import logging
import sys, os
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import urljoin, urlparse, unquote, quote
import aiohttp.client_exceptions
from bs4 import BeautifulSoup
from datetime import datetime
import random
import re
import gzip
import asyncio
import aiofiles
import aiohttp
from aiohttp import ClientSession, TCPConnector
import aiosqlite
import aiofiles.os as aio_os

# 配置日志输出格式，时间格式为 YYYY-MM-DD HH:MM:SS，输出到标准输出
logging.basicConfig(
    format="%(asctime)s %(levelname)s %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("emd")
logging.getLogger("chardet.charsetprober").disabled = True  # 禁用字符集探测日志

# 定义所有支持的媒体路径（URL 编码），用于指定爬取的文件夹
s_paths_all = [
    quote("测试/"),  # 512
    quote("动漫/"),  # 256
    quote("每日更新/"),  # 128
    quote("电影/"),  # 64
    quote("电视剧/"),  # 32
    quote("纪录片/"),  # 16
    quote("纪录片（已刮削）/"),  # 8
    quote("综艺/"),  # 4
    quote("国产剧专属/"),  # 4
    quote("音乐/"),  # 2
    quote("📺画质演示测试（4K，8K，HDR，Dolby）/"),  # 1
]

# 定义必须检查的媒体文件夹（用于 test_media_folder）
t_paths = [
    quote("每日更新/"),
    quote("国产剧专属/"),
]

# 定义默认爬取的路径（如果未指定 --paths 或 --all）
s_paths = [
    quote("每日更新/"),
    quote("国产剧专属/"),
]

# 定义默认的 URL 池，用于爬取媒体文件
s_pool = [
    "http://happyskey.top:8108/",
]

# 定义要忽略的文件夹
s_folder = [".sync"]

# 定义要忽略的文件扩展名（如字幕文件）
s_ext = [".ass", ".srt", ".ssa"]

# 配置自定义 User-Agent，绕过 Cloudflare 限制
CUSTOM_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36"
opener = urllib.request.build_opener()
opener.addheaders = [("User-Agent", CUSTOM_USER_AGENT)]
urllib.request.install_opener(opener)

def pick_a_pool_member(url_list):
    """从 URL 池中随机选择一个可用的 URL"""
    random.shuffle(url_list)
    for member in url_list:
        try:
            logger.debug("测试 URL: %s", member)
            response = urllib.request.urlopen(member)
            if response.getcode() == 200:
                content = response.read()
                try:
                    content_decoded = content.decode("utf-8")
                    if "每日更新" in content_decoded:
                        logger.info("选择 URL: %s", member)
                        return member
                    else:
                        logger.info("URL %s 不包含 '每日更新'", member)
                except UnicodeDecodeError:
                    logger.info("URL %s 返回非 UTF-8 内容", member)
        except Exception as e:
            logger.info("访问 URL %s 失败: %s", member, e)
    return None

def current_amount(url, media, paths):
    """统计远程 scan.list.gz 中指定路径下的文件数量"""
    listfile = os.path.join(media, ".scan.list.gz")
    try:
        res = urllib.request.urlretrieve(url, listfile)
        with gzip.open(listfile) as response:
            pattern = r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2} \/(.*)$"
            hidden_pattern = r"^.*?\/\..*$"
            matching_lines = 0
            for line in response:
                try:
                    line = line.decode(encoding="utf-8").strip()
                    match = re.match(pattern, line)
                    if match:
                        file = match.group(1)
                        if any(file.startswith(unquote(path)) for path in paths):
                            if not re.match(hidden_pattern, file) and not file.lower().endswith(".txt"):
                                matching_lines += 1
                except:
                    logger.error("解码行失败: %s", line)
        return matching_lines
    except urllib.error.URLError as e:
        print("错误:", e)
        return -1

async def fetch_html(url, session, **kwargs) -> str:
    """异步获取 URL 的 HTML 内容"""
    semaphore = kwargs["semaphore"]
    async with semaphore:
        async with session.request(method="GET", url=url) as resp:
            logger.debug("请求头 [%s]: [%s]", unquote(url), resp.request_info.headers)
            resp.raise_for_status()
            logger.debug("响应头 [%s]: [%s]", unquote(url), resp.headers)
            logger.debug("收到响应 [%s] for URL: %s", resp.status, unquote(url))
            try:
                text = await resp.text()
                return text
            except UnicodeDecodeError:
                logger.error("URL %s 返回非 UTF-8 内容", unquote(url))
                return None

async def parse(url, session, max_retries=3, **kwargs) -> set:
    """解析 HTML 页面，提取文件和目录信息"""
    global html
    retries = 0
    files = []
    directories = []
    while True:
        if retries < max_retries:
            try:
                html = await fetch_html(url=url, session=session, **kwargs)
                if html is None:
                    logger.debug("无法获取 URL 的 HTML 内容: %s", unquote(url))
                    return files, directories
                break
            except aiohttp.ClientResponseError as e:
                logger.error(
                    "aiohttp ClientResponseError for %s [%s]: %s. 重试 (%d/%d)...",
                    unquote(url),
                    getattr(e, "status", None),
                    getattr(e, "message", None),
                    retries + 1,
                    max_retries,
                )
                retries += 1
            except (
                aiohttp.ClientError,
                aiohttp.http_exceptions.HttpProcessingError,
                aiohttp.ClientPayloadError,
            ) as e:
                logger.error(
                    "aiohttp 异常 for %s [%s]: %s",
                    unquote(url),
                    getattr(e, "status", None),
                    getattr(e, "message", None),
                )
                return files, directories
            except Exception as e:
                logger.exception("非 aiohttp 异常: %s", getattr(e, "__dict__", {}))
                return files, directories
        else:
            logger.error("达到最大重试次数，URL %s 请求失败", unquote(url))
            return files, directories

    soup = BeautifulSoup(html, "html.parser")
    for link in soup.find_all("a"):
        href = link.get("href")
        # 跳过无效或特殊链接（如排序链接、email-protection）
        if not href or href.startswith("?C=") or "/cdn-cgi/l/email-protection" in href:
            continue
        if (
            href != "../"
            and not href.endswith("/")
            and not href.lower().endswith(".txt")
            and href != "scan.list"
        ):
            try:
                abslink = urljoin(url, href)
                filename = unquote(urlparse(abslink).path)
                # 验证 next_sibling 是否有效
                if not link.next_sibling or not link.next_sibling.strip():
                    logger.debug("URL %s 无有效 next_sibling", href)
                    continue
                # 提取时间戳并验证
                timestamp_str = link.next_sibling.strip().split()[:2]
                if len(timestamp_str) != 2:
                    logger.debug("URL %s 的时间戳数据无效", href)
                    continue
                timestamp = datetime.strptime(" ".join(timestamp_str), "%Y-%m-%d %H:%M")
                timestamp_unix = int(timestamp.timestamp())
                filesize = link.next_sibling.strip().split()[2]
                files.append((abslink, filename, timestamp_unix, filesize))
            except (urllib.error.URLError, ValueError) as e:
                logger.exception("解析 URL 错误: %s", href)
                continue
            except Exception as e:
                logger.exception("URL %s 出现意外错误: %s", href, e)
                continue
        elif href != "../" and not href.lower().endswith(".txt"):
            directories.append(urljoin(url, href))
    return files, directories

async def need_download(file, **kwargs):
    """检查文件是否需要下载（基于存在性、时间戳和文件大小）"""
    url, filename, timestamp, filesize = file
    file_path = os.path.join(kwargs["media"], filename.lstrip("/"))
    if not os.path.exists(file_path):
        logger.debug("%s 不存在", file_path)
        return True
    elif file_path.endswith(".nfo"):
        if not kwargs["nfo"]:
            return False
    current_filesize = os.path.getsize(file_path)
    current_timestamp = os.path.getmtime(file_path)
    logger.debug("%s 的时间戳: %s, 大小: %s", filename, timestamp, filesize)
    if int(filesize) == int(current_filesize) and int(timestamp) <= int(current_timestamp):
        return False
    logger.debug("%s 的当前时间戳: %s, 当前大小: %s", filename, current_timestamp, current_filesize)
    return True

async def download(file, session, **kwargs):
    """异步下载文件并保存到指定路径"""
    url, filename, timestamp, filesize = file
    semaphore = kwargs["semaphore"]
    async with semaphore:
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    file_path = os.path.join(kwargs["media"], filename.lstrip("/"))
                    os.umask(0)
                    os.makedirs(os.path.dirname(file_path), mode=0o777, exist_ok=True)
                    async with aiofiles.open(file_path, "wb") as f:
                        logger.debug("开始写入文件: %s", filename)
                        await f.write(await response.content.read())
                        logger.debug("完成写入文件: %s", filename)
                    os.chmod(file_path, 0o777)
                    logger.info("下载完成: %s", filename)
                else:
                    logger.error("下载失败: %s [响应码: %s]", filename, response.status)
        except Exception as e:
            logger.exception("下载异常: %s", e)

async def download_files(files, session, **kwargs):
    """批量下载文件"""
    download_tasks = set()
    for file in files:
        if await need_download(file, **kwargs) is True:
            task = asyncio.create_task(download(file, session, **kwargs))
            task.add_done_callback(download_tasks.discard)
            download_tasks.add(task)
            if len(download_tasks) > 100:
                await asyncio.gather(*download_tasks)
    await asyncio.gather(*download_tasks)

async def create_table(conn):
    """创建数据库表，用于存储文件信息"""
    try:
        async with conn.execute("""
            CREATE TABLE IF NOT EXISTS files (
                filename TEXT,
                timestamp INTEGER NULL,
                filesize INTEGER NULL)
        """):
            pass
    except Exception as e:
        logger.error("无法创建数据库: %s", e)
        sys.exit(1)

async def insert_files(conn, items):
    """将文件信息插入数据库"""
    await conn.executemany("INSERT OR REPLACE INTO files VALUES (?, ?, ?)", items)
    await conn.commit()

async def exam_file(file, media):
    """检查本地文件的状态（路径、时间戳、大小）"""
    stat = await aio_os.stat(file)
    return file[len(media) :], int(stat.st_mtime), stat.st_size

def process_folder(folder, media):
    """遍历文件夹，收集非隐藏文件和非字幕文件的路径"""
    all_items = []
    for root, dirs, files in os.walk(folder, topdown=False):
        dirs[:] = [d for d in dirs if d not in s_folder]
        for file in files:
            if not file.startswith(".") and not file.lower().endswith(tuple(s_ext)):
                file_path = os.path.join(root, file)
                try:
                    file_path.encode("utf-8")
                    relative_path = file_path[len(media) :]
                except UnicodeEncodeError:
                    logging.error("文件名非 UTF-8 编码: %s", file_path)
                    relative_path = None
                if relative_path:
                    all_items.append((relative_path, None, None))
    return all_items

def remove_empty_folders(paths, media):
    """删除指定路径下的空文件夹"""
    for path in paths:
        for root, dirs, files in os.walk(unquote(os.path.join(media, path)), topdown=False):
            dirs[:] = [d for d in dirs if d not in s_folder]
            if not dirs and not files:
                try:
                    os.rmdir(root)
                    logger.info("删除空文件夹: %s", root)
                except OSError as e:
                    logger.error("无法删除文件夹 %s: %s", root, e)

async def generate_localdb(db, media, paths):
    """生成本地数据库，记录媒体文件信息"""
    logger.warning("正在生成本地数据库... 视磁盘 I/O 性能可能耗时较长，请勿中断...")
    async with aiosqlite.connect(db) as conn:
        await create_table(conn)
        for path in paths:
            logger.info("处理路径: %s", unquote(os.path.join(media, path)))
            items = process_folder(unquote(os.path.join(media, path)), media)
            await insert_files(conn, items)
        total_items_count = await get_total_items_count(conn)
        logger.info("本地磁盘上有 %d 个文件", total_items_count)

async def get_total_items_count(conn):
    """获取数据库中文件总数"""
    async with conn.execute("SELECT COUNT(*) FROM files") as cursor:
        result = await cursor.fetchone()
        total_count = result[0] if result else 0
    return total_count

async def write_one(url, session, db_session, **kwargs) -> list:
    """处理单个 URL，解析并下载文件，返回子目录列表"""
    if urlparse(url).path == "/":
        directories = []
        for path in kwargs["paths"]:
            directories.append(urljoin(url, path))
        return directories
    files, directories = await parse(url=url, session=session, **kwargs)
    if not files:
        return directories
    if kwargs["media"]:
        await download_files(files=files, session=session, **kwargs)
    if db_session:
        items = []
        for file in files:
            items.append(file[1:])
        await db_session.executemany("INSERT OR REPLACE INTO files VALUES (?, ?, ?)", items)
        await db_session.commit()
        logger.debug("已写入 URL 的结果: %s", unquote(url))
    return directories

async def bulk_crawl_and_write(url, session, db_session, depth=0, **kwargs) -> None:
    """递归爬取 URL 和其子目录"""
    tasks = set()
    directories = await write_one(url=url, session=session, db_session=db_session, **kwargs)
    for url in directories:
        task = asyncio.create_task(
            bulk_crawl_and_write(
                url=url,
                session=session,
                db_session=db_session,
                depth=depth + 1,
                **kwargs,
            )
        )
        task.add_done_callback(tasks.discard)
        tasks.add(task)
        if depth == 0:
            await asyncio.gather(*tasks)
    await asyncio.gather(*tasks)

async def compare_databases(localdb, tempdb, total_amount):
    """比较本地和临时数据库，找出已删除的文件"""
    async with aiosqlite.connect(localdb) as conn1, aiosqlite.connect(tempdb) as conn2:
        cursor1 = await conn1.cursor()
        cursor2 = await conn2.cursor()
        await cursor1.execute("SELECT filename FROM files")
        local_filenames = set(filename[0] for filename in await cursor1.fetchall())
        await cursor2.execute("SELECT filename FROM files")
        temp_filenames = set(filename[0] for filename in await cursor2.fetchall())
        gap = abs(len(temp_filenames) - total_amount)
        if gap < 10 and total_amount > 0:
            if not gap == 0:
                logger.warning(
                    "文件总数不匹配: %d -> %d，差距 %d 小于 10，继续清理...",
                    total_amount,
                    len(temp_filenames),
                    abs(len(temp_filenames) - total_amount),
                )
            diff_filenames = local_filenames - temp_filenames
            return diff_filenames
        else:
            logger.error("文件总数不匹配: %d -> %d，跳过清理", total_amount, len(temp_filenames))
            return []

async def purge_removed_files(localdb, tempdb, media, total_amount):
    """删除本地数据库中不存在于远程的文件"""
    for file in await compare_databases(localdb, tempdb, total_amount):
        logger.info("清理文件: %s", file)
        try:
            os.remove(media + file)
        except Exception as e:
            logger.error("无法删除文件 %s: %s", file, e)

def test_media_folder(media, paths):
    """检查媒体目录是否包含必要的子文件夹"""
    t_paths = [os.path.join(media, unquote(path)) for path in paths]
    if all(os.path.exists(os.path.abspath(path)) for path in t_paths):
        return True
    else:
        return False

def load_paths_from_file(path_file):
    """从文件中加载路径列表"""
    paths = []
    try:
        with open(path_file, "r", encoding="utf-8") as file:
            for line in file:
                stripped_line = line.strip()
                if stripped_line:
                    encoded_path = quote(stripped_line)
                    if is_subpath(encoded_path, s_paths_all):
                        paths.append(encoded_path)
                    else:
                        logging.error("无效路径: %s", unquote(encoded_path))
                        return []
    except Exception as e:
        logging.error("加载路径文件失败: %s", str(e))
    return paths

def is_subpath(path, base_paths):
    """检查路径是否为指定路径的子路径"""
    for base_path in base_paths:
        if path.startswith(base_path):
            return True
    return False

def get_paths_from_bitmap(bitmap, paths_all):
    """根据位图选择路径"""
    max_bitmap_value = (1 << len(paths_all)) - 1
    if bitmap < 0 or bitmap > max_bitmap_value:
        raise ValueError(f"位图值 {bitmap} 超出范围，必须在 0 到 {max_bitmap_value} 之间")
    selected_paths = []
    binary_representation = bin(bitmap)[2:].zfill(len(paths_all))
    for i, bit in enumerate(binary_representation):
        if bit == "1":
            selected_paths.append(paths_all[i])
    return selected_paths

async def main():
    """主函数，处理命令行参数并启动爬取"""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--media",
        metavar="<folder>",
        type=str,
        default=None,
        required=True,
        help="存储下载媒体文件的路径 [默认: %(default)s]",
    )
    parser.add_argument(
        "--count",
        metavar="[number]",
        type=int,
        default=100,
        help="最大并发 HTTP 请求数 [默认: %(default)s]",
    )
    parser.add_argument(
        "--debug",
        action=argparse.BooleanOptionalAction,
        type=bool,
        default=False,
        help="启用详细调试日志 [默认: %(default)s]",
    )
    parser.add_argument(
        "--db",
        action=argparse.BooleanOptionalAction,
        type=bool,
        default=False,
        help="<需要 Python 3.12+> 保存到数据库 [默认: %(default)s]",
    )
    parser.add_argument(
        "--nfo",
        action=argparse.BooleanOptionalAction,
        type=bool,
        default=False,
        help="下载 NFO 文件 [默认: %(default)s]",
    )
    parser.add_argument(
        "--url",
        metavar="[url]",
        type=str,
        default=None,
        help="下载路径 [默认: %(default)s]",
    )
    parser.add_argument(
        "--purge",
        action=argparse.BooleanOptionalAction,
        type=bool,
        default=True,
        help="清理已删除的文件 [默认: %(default)s]",
    )
    parser.add_argument(
        "--all",
        action=argparse.BooleanOptionalAction,
        type=bool,
        default=False,
        help="下载所有文件夹 [默认: %(default)s]",
    )
    parser.add_argument(
        "--location",
        metavar="<folder>",
        type=str,
        default=None,
        required=None,
        help="存储数据库文件的路径 [默认: %(default)s]",
    )
    parser.add_argument(
        "--paths",
        metavar="<file>",
        type=str,
        help="路径的位图或包含路径的文件 (参考 paths.example)",
    )

    args = parser.parse_args()
    if args.debug:
        logging.getLogger("emd").setLevel(logging.DEBUG)
    logging.info("*** xiaoya_emd version 1.6.15 ***")
    paths = []
    if args.all:
        paths = s_paths_all
        s_pool.pop(0)
        if args.purge:
            args.db = True
    else:
        if args.paths:
            paths_from_file = []
            is_bitmap = False
            try:
                paths_bitmap = int(args.paths)
                paths_from_file = get_paths_from_bitmap(paths_bitmap, s_paths_all)
                is_bitmap = True
            except ValueError:
                logging.info("路径参数不是位图，尝试从文件加载")
            if not is_bitmap:
                paths_from_file = load_paths_from_file(args.paths)
            if not paths_from_file:
                logging.error("路径文件不包含有效路径或位图值错误: %s", args.paths)
                sys.exit(1)
            for path in paths_from_file:
                if not is_subpath(path, s_paths):
                    s_pool.pop(0)
                    break
            paths.extend(paths_from_file)
        if not paths:
            paths = s_paths

    if args.media:
        if not os.path.exists(os.path.join(args.media, "115")):
            logging.warning("115 文件夹不存在，正在创建...此解决方法将在下个版本移除")
            os.makedirs(os.path.join(args.media, "115"))
        if not test_media_folder(args.media, t_paths):
            logging.error("路径 %s 不包含所需文件夹，请修正 --media 参数", args.media)
            sys.exit(1)
        else:
            media = args.media.rstrip("/")
    if not args.url:
        url = pick_a_pool_member(s_pool)
    else:
        url = args.url
    if urlparse(url).path != "/" and (args.purge or args.db):
        logger.warning("--db 或 --purge 仅支持根路径模式")
        sys.exit(1)
    if not url:
        logger.info("无法连接到任何服务器，请检查网络连接...")
        sys.exit(1)
    if urlparse(url).path == "/":
        total_amount = current_amount(url + ".scan.list.gz", media, paths)
        logger.info("%s 中有 %d 个文件", url, total_amount)
    semaphore = asyncio.Semaphore(args.count)
    db_session = None
    if args.db or args.purge:
        assert sys.version_info >= (3, 12), "数据库功能需要 Python 3.12+"
        if args.location:
            if test_db_folder(args.location) is True:
                db_location = args.location.rstrip("/")
            else:
                sys.exit(1)
        else:
            db_location = media
        localdb = os.path.join(db_location, ".localfiles.db")
        tempdb = os.path.join(db_location, ".tempfiles.db")
        if not os.path.exists(localdb):
            await generate_localdb(localdb, media, paths)
        elif args.db:
            os.remove(localdb)
            await generate_localdb(localdb, media, paths)
        else:
            async with aiosqlite.connect(localdb) as local_session:
                local_amount = await get_total_items_count(local_session)
                if (
                    local_amount > 0
                    and total_amount > 0
                    and abs(total_amount - local_amount) > 1000
                ):
                    logger.warning("本地数据库不完整，正在重新生成...")
                    await local_session.execute("DELETE FROM files")
                    await local_session.commit()
                    await generate_localdb(localdb, media, paths)
        db_session = await aiosqlite.connect(tempdb)
        await create_table(db_session)
    logger.info("开始缓慢爬取...")
    async with ClientSession(
        connector=TCPConnector(ssl=False, limit=0, ttl_dns_cache=600),
        timeout=aiohttp.ClientTimeout(total=36000),
    ) as session:
        await bulk_crawl_and_write(
            url=url,
            session=session,
            db_session=db_session,
            semaphore=semaphore,
            media=media,
            nfo=args.nfo,
            paths=paths,
        )
    if db_session:
        await db_session.commit()
        await db_session.close()
    if args.purge:
        await purge_removed_files(localdb, tempdb, media, total_amount)
        remove_empty_folders(paths, media)
        os.remove(localdb)
        if not args.all:
            os.rename(tempdb, localdb)
        else:
            os.remove(tempdb)
    logger.info("完成...")

if __name__ == "__main__":
    assert sys.version_info >= (3, 10), "脚本需要 Python 3.10+"
    asyncio.run(main())
