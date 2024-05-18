import csv
import time
import requests
import threading
import datetime

# Parameters
url = 'http://10.0.0.1'
num_requests = 128
sleep_time = 0.08
batch_delay = 15  # Delay between batches in seconds
num_batches = 32

def send_request():
    start_time = time.time()
    response = requests.get(url)
    end_time = time.time()

    # Update total data received and total time
    lock.acquire()
    total_data[0] += len(response.content)
    total_time[0] += end_time - start_time
    lock.release()

# Prepare CSV file
csvFile = '/tmp/data_{}.csv'.format(datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S'))
with open(csvFile, 'w') as file:
    writer = csv.writer(file)
    writer.writerow(["Batch", "Throughput (bytes/second)"])

    # Send requests in batches
    for i in range(num_batches):
        total_data = [0]
        total_time = [0]
        lock = threading.Lock()

        threads = []
        for _ in range(num_requests):
            thread = threading.Thread(target=send_request)
            threads.append(thread)
            thread.start()
            time.sleep(sleep_time)

        # Wait for all threads to finish
        for thread in threads:
            thread.join()

        # Calculate and print throughput (bytes per second) for each batch
        throughput = total_data[0] / total_time[0]
        print('Batch {}: Throughput: {} bytes/second'.format(i+1, throughput))

        # Write to CSV
        writer.writerow([i+1, throughput])

        # Delay before next batch
        time.sleep(batch_delay)
