from win11toast import toast

class Notification:
    def __init__(self, title, description,onclick=None):
        self.title = title
        self.description = description
        self.onclick=onclick
    def view(self):
        toast(self.title, self.description,
              on_click=self.onclick)

#Notification("title","description",onclick=lambda *args: print("hello")).view()