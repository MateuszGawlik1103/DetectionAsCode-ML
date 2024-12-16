import csv


def csv_append(file_name, *params):
    with open(file_name, "a", newline="") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(params)


def csv_read(file_name):
    with open(file_name, "r") as csv_file:
        csv_reader = csv.reader(csv_file)
        data = [row for row in csv_reader]
        return data
