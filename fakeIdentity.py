from faker import Faker

def create_fake_identity():
    fake = Faker()
    fake_name = fake.name()
    fake_adress=fake.address()
    fake_mail=fake.email()
    fake_phone=fake.phone_number()

    return fake_name,fake_mail,fake_adress,fake_phone


