import subprocess
import os

DEFAULT_TMP_FOLDER = 'tmp'
class Adapter:
    def __init__(self, tmp_folder=None) -> None:
        self.tmp = tmp_folder if tmp_folder is not None else DEFAULT_TMP_FOLDER
        if not os.path.exists(self.tmp):
            os.makedirs(self.tmp)
        
    def run_cmd(self, cmd):
        result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
        if result.returncode != 0:
            print (result.stderr)
            raise Exception(result.stderr)
        return result
    
    def cleanup(self):
        subprocess.run('rm -rf {}'.format(self.tmp), shell=True, stdout=subprocess.PIPE)