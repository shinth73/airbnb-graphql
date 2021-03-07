from .models import User


def resolve_user(self, info, id):
    return User.objects.get(id=id)


def resolve_me(root, info):
    user = info.context.user
    print(user.is_authenticated)
    if user.is_authenticated:
        return info.context.user
    else:
        raise Exception("You need to be logged in")
