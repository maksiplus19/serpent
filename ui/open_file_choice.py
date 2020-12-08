# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'open_file_choice.ui'
#
# Created by: PyQt5 UI code generator 5.15.1
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QDialog


class Ui_ChoiceDialog(QDialog):
    def __init__(self):
        super(Ui_ChoiceDialog, self).__init__()
        self.setupUi()
        self.originalButton.clicked.connect(self.or_button_click)
        self.encryptButton.clicked.connect(self.en_button_click)
        self.decryptButton.clicked.connect(self.de_button_click)
        self.choice = None

    def setupUi(self):
        self.setObjectName("ChoiceDialog")
        self.resize(250, 154)
        self.verticalLayout = QtWidgets.QVBoxLayout(self)
        self.verticalLayout.setObjectName("verticalLayout")
        self.originalButton = QtWidgets.QPushButton(self)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.originalButton.setFont(font)
        self.originalButton.setObjectName("originalButton")
        self.verticalLayout.addWidget(self.originalButton)
        self.encryptButton = QtWidgets.QPushButton(self)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.encryptButton.setFont(font)
        self.encryptButton.setObjectName("encryptButton")
        self.verticalLayout.addWidget(self.encryptButton)
        self.decryptButton = QtWidgets.QPushButton(self)
        font = QtGui.QFont()
        font.setPointSize(12)
        self.decryptButton.setFont(font)
        self.decryptButton.setProperty("choice", 0)
        self.decryptButton.setObjectName("decryptButton")
        self.verticalLayout.addWidget(self.decryptButton)

        self.retranslateUi(self)
        QtCore.QMetaObject.connectSlotsByName(self)

    def retranslateUi(self, ChoiceDialog):
        _translate = QtCore.QCoreApplication.translate
        ChoiceDialog.setWindowTitle(_translate("ChoiceDialog", "Dialog"))
        self.originalButton.setText(_translate("ChoiceDialog", "Оригинальный файл"))
        self.encryptButton.setText(_translate("ChoiceDialog", "Зашифрованный файл"))
        self.decryptButton.setText(_translate("ChoiceDialog", "Дешифрованный файл"))

    def or_button_click(self):
        self.choice = 0
        self.accept()

    def en_button_click(self):
        self.choice = 1
        self.accept()

    def de_button_click(self):
        self.choice = 2
        self.accept()