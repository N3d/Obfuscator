from cx_Freeze import setup, Executable

executables = [
    Executable('exfiltrator.py')
]

setup(name='exfiltrator',
      version='0.1',
      description='Exfiltrator script',
      executables=executables
      )