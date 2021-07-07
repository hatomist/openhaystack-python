from AirTagCrypto import AirTagCrypto
import requests
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import ASYNCHRONOUS
from datetime import datetime
from config import *

client = InfluxDBClient(url=influxdb_url, token=influxdb_token, org=influxdb_org)
write_api = client.write_api(write_options=ASYNCHRONOUS)

if __name__ == "__main__":
    tags = {}

    for key in private_keys:
        tag = AirTagCrypto(key)
        tags[tag.get_advertisement_key()] = tag

    data = requests.post(simple_server_url, json={"ids": list(tags.keys())}).json()

    for result in data['results']:
        decrypt = tags[result['id']].decrypt_message(result['payload'])
        date_time = datetime.fromtimestamp(int(result['datePublished'])/1000)
        write_api.write(influxdb_db, influxdb_org, Point(result['id'])
                        .tag('report_id', str(hash(result['payload'])))
                        .field('latitude', decrypt['lat'])
                        .field("longitude", decrypt['lon'])
                        .field("tooltip", date_time.strftime("%d/%m/%Y %H:%M:%S"))
                        .time(decrypt['timestamp'] * 1000000000))
    write_api.flush()
