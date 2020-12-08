from PyQt5.QtCore import QObject, pyqtSignal


class UpdateSignal(QObject):
    update = pyqtSignal(int)
