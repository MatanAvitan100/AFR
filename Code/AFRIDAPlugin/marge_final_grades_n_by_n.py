
import json

base = 'C:\/Users\User\/Desktop\/Final Project\/Statistics\/' # 'I:\/Final Project\/Statistics\/'

def json_read(file):
    with open(file) as json_file:
        data = json.load(json_file)
    return data

def json_write(file, data):
    with open(file, 'w') as json_file:
        json.dump(data, json_file)


final_grades_0=json_read(base + "final_grades_n_by_n_0.txt")
final_grades_1=json_read(base + "final_grades_n_by_n_1.txt")
final_grades_2=json_read(base + "final_grades_n_by_n_2.txt")

final_grades_0.update(final_grades_1)
final_grades_0.update(final_grades_2)

f = open(base + "kkk", 'w')
  
f.write(json.dumps(final_grades_0, indent=2))
f.flush()
f.close()
	