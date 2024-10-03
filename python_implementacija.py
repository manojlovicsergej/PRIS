import tkinter as tk
from tkinter import messagebox, Toplevel, Checkbutton, IntVar
import googlemaps
import webbrowser
import sqlite3
import hashlib
from fpdf import FPDF
import os
import requests
from tkinter import simpledialog





# Povezivanje na SQLite bazu podataka
conn = sqlite3.connect('app.db')
c = conn.cursor()


# Kreiranje tabele za rute (personalizovane rute korisnika)
c.execute('''
CREATE TABLE IF NOT EXISTS routes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    route_name TEXT,  -- Dodana kolona za naziv rute
    landmarks TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
''')


# Kreiranje tabele korisnika (admin, pisci sadržaja, obični korisnici)
c.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    email TEXT,
    password TEXT,
    role TEXT  -- admin, content_writer, registered_user
)
''')

# Kreiranje tabele za znamenitosti (pišu ih pisci sadržaja)
c.execute('''
CREATE TABLE IF NOT EXISTS landmarks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    short_description TEXT,  -- Kraći opis znamenitosti
    description TEXT,
    location TEXT,
    image_url TEXT
)
''')

conn.commit()
# Dodaj novu kolonu 'epoch' u tabelu 'landmarks'

# Funkcija za brisanje znamenitosti iz baze
def delete_landmark_by_name_part(name_part):
    try:
        # Koristimo LIKE za brisanje znamenitosti koja sadrži "name_part"
        c.execute("DELETE FROM landmarks WHERE name LIKE ?", ('%' + name_part + '%',))
        conn.commit()
        
        # Proveravamo da li je nešto obrisano
        if c.rowcount > 0:
            messagebox.showinfo("Uspeh", f"Znamenitost sa '{name_part}' u imenu je obrisana.")
        else:
            messagebox.showwarning("Upozorenje", f"Nema znamenitosti sa '{name_part}' u imenu.")
    except Exception as e:
        messagebox.showerror("Greška", f"Došlo je do greške: {e}")

# Funkcija za hesiranje lozinki
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Funkcija za registraciju korisnika
def register_user(username, email, password, role):
    hashed_password = hash_password(password)
    c.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)", 
              (username, email, hashed_password, role))
    conn.commit()

# Funkcija za logovanje korisnika
def login_user(username, password):
    hashed_password = hash_password(password)
    c.execute("SELECT * FROM users WHERE username=? AND password=?", (username, hashed_password))
    user = c.fetchone()
    if user:
        return user  # Vraća podatke o korisniku ako su uneti podaci ispravni
    else:
        return None  # Logovanje nije uspelo

# Funkcija za generisanje PDF vodiča sa lokalnim slikama na osnovu odabranih opcija
def generate_pdf(landmarks, short_desc_selected, long_desc_selected, epoch_desc_selected):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font('Arial', 'B', 16)
    pdf.cell(200, 10, txt="Tour Guide", ln=True, align='C')

    pdf.set_font('Arial', '', 12)

    # Praćenje epoha koje su već obrađene
    processed_epochs = set()

    for landmark in landmarks:
        name = landmark[1]  # Ime znamenitosti
        short_description = landmark[5]  # Kraći opis znamenitosti
        long_description = landmark[2]  # Duži opis znamenitosti
        epoch_id = landmark[6]  # ID epohe (pretpostavka da se epohe identifikuju ovim ID-jem)
        image_path = landmark[4]  # Putanja do lokalne slike

        # Dodavanje naslova znamenitosti
        pdf.ln(10)
        pdf.cell(200, 10, txt=name, ln=True, align='L')

        # Proveravamo da li treba prikazati opis epohe
        if epoch_desc_selected and epoch_id not in processed_epochs:
            epoch_description = get_epoch_description(epoch_id)  # Funkcija koja vraća opis epohe na osnovu ID-a
            if epoch_description:
                pdf.ln(5)
                pdf.set_font('Arial', 'B', 12)
                pdf.cell(200, 10, txt=f"Epoha: {epoch_description[0]}", ln=True)  # Naziv epohe
                pdf.set_font('Arial', '', 12)
                pdf.multi_cell(0, 10, epoch_description[1])  # Opis epohe
                processed_epochs.add(epoch_id)  # Beležimo da smo obradili ovu epohu

        # Dodavanje kraćeg opisa
        if short_desc_selected:
            pdf.ln(5)
            pdf.multi_cell(0, 10, f"Kraći opis: {short_description}")

        # Dodavanje dužeg opisa
        if long_desc_selected:
            pdf.ln(5)
            pdf.multi_cell(0, 10, f"Duži opis: {long_description}")

        # Dodavanje slike
        if image_path and os.path.exists(image_path):
            try:
                pdf.ln(5)
                pdf.image(image_path, w=100, h=75)
            except Exception as e:
                print(f"Greška prilikom dodavanja slike u PDF: {e}")
        else:
            pdf.ln(5)
            pdf.cell(200, 10, txt="Slika nije dostupna", ln=True, align='L')

    # Čuvanje PDF-a
    pdf_file = "tour_guide.pdf"
    pdf.output(pdf_file)

    # Otvori PDF nakon generisanja
    os.system(f'start {pdf_file}')  # Windows; za macOS/Linux koristi open ili xdg-open

# Funkcija za preuzimanje imena i opisa epohe na osnovu epoch_id
def get_epoch_data(epoch_id):
    c.execute("SELECT epoch_name, epoch_description FROM epohe WHERE id=?", (epoch_id,))
    result = c.fetchone()
    return result if result else (None, None)

# Funkcija za preuzimanje opisa epohe na osnovu epoch_id
def get_epoch_description(epoch_id):
    c.execute("SELECT epoch_description FROM epohe WHERE id=?", (epoch_id,))
    result = c.fetchone()
    return result[0] if result else None
# Ažuriranje opisa epoha u tabeli 'epohe'
epoch_descriptions = [
    ("U ovoj fazi dominiraju vizantijski uticaji, narocito u crkvenoj arhitekturi. Primeri su ranohriscanske bazilike i crkve, a kljucni elementi ukljucuju kupole, krstasto-kupolne planove i mozaike. Jedan od najpoznatijih primera iz ovog perioda je Crkva Svetog Petra u Rasu.", 1),
    ("Ova faza je poznata po raskom stilu crkava, koje su kombinacija vizantijske arhitekture i zapadnoevropskih (romanickih) elemenata. Manastir Studenica je jedan od najvaznijih primera ovog stila, sa jednostavnim spoljnim izgledom, ali raskosnim unutrasnjim dekoracijama.", 2),
    ("Ova epoha se razvija u periodu dinastije Lazarevica i Brankovica. Stil je prepoznatljiv po bogato ukrasenim fasadama sa floralnim motivima, kupolama i mnogougaonim oltarima. Manastiri poput Manasije i Ravanicke su karakteristicni primeri ovog perioda.", 3),
    ("Tokom perioda osmanske vlasti, u gradevinarstvu dominiraju elementi islamske arhitekture, posebno u urbanim sredinama. Ovaj stil se vidi u gradevinama kao sto su dzamije, hamami i hanovi. Najpoznatiji primer je Bajrakli dzamija u Beogradu.", 4),
    ("U periodu habsburske dominacije na severu Srbije (Vojvodina), dolazi do uticaja baroka i klasicizma. Gradovi kao sto su Sremski Karlovci i Novi Sad imaju mnoge gradevine sa ovim stilovima, ukljucujuci gradske kuce, crkve i javne zgrade.", 5),
    ("U periodu nacionalne obnove, mnoge gradevine u Srbiji grade se u neoromanticnom i neobizantijskom stilu, kao izraz srpskog nacionalnog identiteta. Hram Svetog Save u Beogradu je jedan od najvaznijih simbola ovog perioda.", 6),
    ("U periodu izmedu dva svetska rata, dolazi do pojave modernizma, sa uticajem Bauhausa i konstruktivizma. Beograd i drugi veci gradovi dozivljavaju brzi urbanisticki razvoj. Palata Albanija je jedan od prvih nebodera izgradenih u ovom stilu.", 7),
    ("Nakon Drugog svetskog rata, u periodu socijalisticke Jugoslavije, mnoge zgrade su gradene u stilu socijalistickog realizma, sa naglaskom na monumentalne gradevine, dok se kasnije razvija brutalizam, sa karakteristicnom upotrebom betona. Dom omladine i Palata Srbije u Beogradu su primeri ove arhitekture.", 8),
    ("Od kraja 20. veka do danas, arhitektura Srbije prati globalne trendove, sa naglaskom na savremeni minimalizam, funkcionalizam i koriscenje novih materijala poput stakla i celika. Primeri su moderni poslovni centri i stambeni kompleksi kao sto je Beograd na vodi.", 9)
]

# Izvrši ažuriranje za svaku epohu
for description, id in epoch_descriptions:
    c.execute("UPDATE epohe SET epoch_description = ? WHERE id = ?", (description, id))
conn.commit()

# Funkcija za generisanje PDF vodiča sa lokalnim slikama
def generate_pdf(landmarks, short_desc, long_desc, epoch_desc):
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    pdf.set_font('Arial', 'B', 16)
    pdf.cell(200, 10, txt="Tour Guide", ln=True, align='C')

    pdf.set_font('Arial', '', 12)

    # Kreiramo set epoha koje su već obrađene kako se ne bi duplirale
    processed_epochs = set()

    for landmark in landmarks:
        name = landmark[1]  # Ime znamenitosti
        short_description = landmark[5]  # Kraci opis
        long_description = landmark[2]  # Dugi opis
        epoch_id = landmark[9]  # ID epohe

        # Prikazivanje opisa epohe ako je opcija selektovana i epoha nije već prikazana
        if epoch_desc and epoch_id not in processed_epochs:
            epoch_name, epoch_description = get_epoch_data(epoch_id)
            if epoch_name and epoch_description:
                pdf.ln(10)
                pdf.set_font('Arial', 'B', 14)
                pdf.cell(200, 10, txt=f"{epoch_name}", ln=True, align='L')  # Ime epohe kao naslov
                pdf.set_font('Arial', '', 12)
                pdf.multi_cell(0, 10, epoch_description)  # Opis epohe
                processed_epochs.add(epoch_id)  # Dodaj epohu u set da je ne ponavljamo

        # Dodavanje znamenitosti
        pdf.ln(10)
        pdf.set_font('Arial', 'B', 12)
        pdf.cell(200, 10, txt=name, ln=True, align='L')  # Naslov znamenitosti
        pdf.set_font('Arial', '', 12)

        # Dodavanje opisa znamenitosti na osnovu selekcije korisnika
        if short_desc:
            pdf.multi_cell(0, 10, short_description)
        if long_desc:
            pdf.multi_cell(0, 10, long_description)

        # Dodavanje slike ako postoji
        image_path = landmark[4]  # Putanja do lokalne slike
        if image_path and os.path.exists(image_path):
            try:
                pdf.image(image_path, w=100, h=75)
            except Exception as e:
                print(f"Greška prilikom dodavanja slike u PDF: {e}")
        else:
            pdf.cell(200, 10, txt="Slika nije dostupna", ln=True, align='L')

    # Čuvanje PDF-a
    pdf_file = "tour_guide.pdf"
    pdf.output(pdf_file)

    # Otvori PDF nakon generisanja
    os.system(f'start {pdf_file}')  # Windows; za macOS/Linux koristi open ili xdg-open

# Funkcija za generisanje rute pomoću Google Maps API i kreiranje PDF-a sa odabranim opcijama
def generate_route_and_pdf(landmarks, short_desc_selected, long_desc_selected, epoch_desc_selected):
    gmaps = googlemaps.Client(key='')  
   
    locations = [landmark[3] for landmark in landmarks]  # Uzimamo lokacije iz baze

    if len(locations) < 2:
        messagebox.showerror("Greška", "Morate izabrati barem dve lokacije za kreiranje rute!")
        return
    
    try:
        # Dobijanje optimalne rute koristeći Distance Matrix API za pešačenje
        matrix = gmaps.distance_matrix(origins=locations, destinations=locations, mode="walking")

        # Generisanje URL-a za Google Maps rutu
        base_url = "https://www.google.com/maps/dir/?api=1&"
        origin = locations[0]
        destination = locations[-1]
        waypoints = '|'.join(locations[1:-1])

        if waypoints:
            maps_url = f"{base_url}origin={origin}&destination={destination}&waypoints={waypoints}&travelmode=walking"
        else:
            maps_url = f"{base_url}origin={origin}&destination={destination}&travelmode=walking"

        # Otvaranje rute u pretraživaču
        webbrowser.open(maps_url)

        # Generisanje PDF vodiča sa odabranim opcijama
        generate_pdf(landmarks, short_desc_selected, long_desc_selected, epoch_desc_selected)

    except Exception as e:
        messagebox.showerror("Greška", f"Nešto nije u redu: {e}")


conn.commit()

# Funkcija za čuvanje rute u bazi
def save_route(user_id, route_name, selected_landmarks):
    # Transformišemo znamenitosti u string
    landmarks_string = ','.join([landmark[1] for landmark in selected_landmarks])  # Čuva imena znamenitosti
    c.execute("INSERT INTO routes (user_id, route_name, landmarks) VALUES (?, ?, ?)", 
              (user_id, route_name, landmarks_string))
    conn.commit()
    messagebox.showinfo("Uspeh", f"Ruta '{route_name}' je uspešno sačuvana!")


# Funkcija za preuzimanje svih ruta korisnika
def get_user_routes(user_id):
    c.execute("SELECT * FROM routes WHERE user_id=?", (user_id,))
    return c.fetchall()

# Funkcija za preuzimanje znamenitosti iz sačuvane rute
def get_landmarks_from_route(route):
    # Četvrti element (index 3) u 'route' je string znamenitosti
    landmarks_string = route  # Kolona 'landmarks' čuva imena znamenitosti u ruti
    landmark_names = landmarks_string.split(',') if landmarks_string else []  # Delimo string po zarezima

    if not landmark_names:
        return []  # Ako nema znamenitosti, vraća prazan spisak

    # Preuzimamo znamenitosti po imenima
    return get_landmarks_by_names(landmark_names)  # Funkcija vraća listu objekata znamenitosti

# Funkcija za učitavanje sačuvane rute (sa dugmetom za zatvaranje)
def load_saved_route(user):
    routes = get_user_routes(user[0])  # Preuzimanje svih ruta korisnika
    if not routes:
        messagebox.showwarning("Upozorenje", "Nemate sačuvanih ruta.")
        return

    # Frame za sačuvane rute, koji ćemo ukloniti kad zatvorimo učitavanje
    load_route_frame = tk.Frame(root)
    load_route_frame.pack(pady=10)

    saved_route_var = tk.StringVar()
    saved_route_var.set("Izaberite sačuvanu rutu")

    # Kreiramo listu opcija u željenom formatu
    route_options = [f"{route[2]} - {route[3]}" for route in routes]  # route[2] je naziv rute, route[3] je lista znamenitosti

    # Kreiramo OptionMenu za učitane rute
    route_dropdown = tk.OptionMenu(load_route_frame, saved_route_var, *route_options)
    route_dropdown.config(font=("Arial", 12), width=40, bg="#f0f0f0", fg="black")
    route_dropdown.pack(side="top", padx=5, pady=5)

    # Funkcija za otvaranje rute
    def open_route():
        for route in routes:
            if saved_route_var.get() == f"{route[2]} - {route[3]}":  # Proveravamo koja ruta je odabrana
                # Preuzimanje znamenitosti sačuvanih u ruti (koristeći imena iz stringa)
                landmarks_in_route = get_landmarks_from_route(route[2])  # Prosleđujemo ceo zapis iz tabele
                # Provera da li su znamenitosti ispravno preuzete
                if landmarks_in_route and len(landmarks_in_route) > 0:
                    # Generisanje PDF-a sa preuzetim znamenitostima
                    generate_route_and_pdf(landmarks_in_route)
                else:
                    messagebox.showerror("Greška", "Neuspešno otvaranje rute.")

    # Kreiramo dugmad za otvaranje i zatvaranje učitavanja rute
    buttons_frame = tk.Frame(load_route_frame)
    buttons_frame.pack(pady=5)

    # Dugme za otvaranje rute
    open_route_btn = tk.Button(buttons_frame, text="Otvori rutu", command=open_route, font=("Arial", 12), bg="#4CAF50", fg="white", width=10, height=2)
    open_route_btn.pack(side="left", padx=5)

    # Funkcija za zatvaranje učitavanja ruta (uklanjanje OptionMenu i vraćanje na default prikaz)
    def close_load_route():
        load_route_frame.destroy()  # Uklanjamo celu sekciju za učitavanje ruta

    # Dugme za zatvaranje učitavanja ruta
    close_route_btn = tk.Button(buttons_frame, text="Zatvori rute", command=close_load_route, font=("Arial", 12), bg="#d9534f", fg="white", width=10, height=2)
    close_route_btn.pack(side="left", padx=5)


# Funkcija za preuzimanje svih podataka o znamenitostima na osnovu imena
def get_landmarks_by_names(landmark_names):
    # Pretvaramo imena znamenitosti u placeholder-e za SQL upit
    placeholders = ', '.join('?' for _ in landmark_names)  # Pravimo placeholder za svako ime
    c.execute(f"SELECT * FROM landmarks WHERE name IN ({placeholders})", landmark_names)
    return c.fetchall()  # Vraćamo ceo red iz tabele za svaku znamenitost



def save_route(user_id, route_name, selected_landmarks):
    # Konvertuj listu znamenitosti u string razdvojen zarezima
    landmark_names = ','.join([landmark[1] for landmark in selected_landmarks])  # Uzimamo ime znamenitosti
    c.execute("INSERT INTO routes (user_id, route_name, landmarks) VALUES (?, ?, ?)",
              (user_id, route_name, landmark_names))
    conn.commit()
    messagebox.showinfo("Uspeh", "Ruta uspešno sačuvana.")


# Funkcija za unos imena rute i poziv funkcije za čuvanje rute
def save_route_prompt(user, selected_landmarks):
    if selected_landmarks:
        route_name = simpledialog.askstring("Naziv rute", "Unesite naziv za rutu:")
        if route_name:
            save_route(user[0], route_name, selected_landmarks)
    else:
        messagebox.showerror("Greška", "Morate izabrati barem jednu znamenitost pre nego što sačuvate rutu.")

# Funkcija za preuzimanje svih znamenitosti
def get_all_landmarks():
    c.execute("SELECT * FROM landmarks")
    return c.fetchall()

# Funkcija za dodavanje znamenitosti (za pisce sadržaja)
def add_landmark(name, short_description, description, location, image_url):
    c.execute("INSERT INTO landmarks (name, description, location, image_url, short_description) VALUES (?, ?, ?, ?, ?)", 
              (name, short_description, description, location, image_url))
    conn.commit()
   # Funkcija za prikaz menija za pisca sadržaja sa opcijama

# Funkcija za prikazivanje menija za Content Writer-a
def content_writer_menu(user):
    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text="Dobrodošli, Content Writer", font=("Arial", 16, "bold")).pack(pady=20)

    # Dodaj dve opcije sa stilizacijom
    tk.Button(root, text="Dodaj novu znamenitost", command=lambda: content_writer_add_landmark(user),
              font=("Arial", 12), bg="#5cb85c", fg="white", width=30, height=2).pack(pady=10)

    tk.Button(root, text="Kreiraj rutu i pregledaj sačuvane rute", command=lambda: registered_user_menu(user),
              font=("Arial", 12), bg="#0275d8", fg="white", width=30, height=2).pack(pady=10)

    # Dugme za logout na dnu
    tk.Button(root, text="Logout", command=start_page, font=("Arial", 12), bg="#d9534f", fg="white", width=30, height=2).pack(side="bottom", pady=20)


# Funkcija koja prikazuje formu za dodavanje nove znamenitosti
def content_writer_add_landmark(user):
    for widget in root.winfo_children():
        widget.destroy()

    # Postojeća funkcionalnost za dodavanje znamenitosti
    tk.Label(root, text="Dodaj novu znamenitost", font=("Arial", 16, "bold")).pack(pady=10)

    # Stilizovano polje za unos imena znamenitosti
    tk.Label(root, text="Ime znamenitosti:", font=("Arial", 12)).pack(anchor="w", padx=10)
    name_entry = tk.Entry(root, font=("Arial", 12), width=40)
    name_entry.pack(pady=5)

    # Stilizovano polje za kraći opis (maksimalno 20 karaktera)
    tk.Label(root, text="Kraći opis (do 20 karaktera):", font=("Arial", 12)).pack(anchor="w", padx=10)
    short_description_entry = tk.Entry(root, font=("Arial", 12), width=40)
    short_description_entry.pack(pady=5)

    # Stilizovano polje za duži opis (više linija)
    tk.Label(root, text="Dugi opis:", font=("Arial", 12)).pack(anchor="w", padx=10)
    description_entry = tk.Text(root, font=("Arial", 12), width=40, height=8)  # Polje za unos dužeg opisa u visinu
    description_entry.pack(pady=5)

    # Stilizovano polje za unos lokacije
    tk.Label(root, text="Lokacija (adresa):", font=("Arial", 12)).pack(anchor="w", padx=10)
    location_entry = tk.Entry(root, font=("Arial", 12), width=40)
    location_entry.pack(pady=5)

    # Stilizovano polje za unos URL-a slike
    tk.Label(root, text="URL slike:", font=("Arial", 12)).pack(anchor="w", padx=10)
    image_url_entry = tk.Entry(root, font=("Arial", 12), width=40)
    image_url_entry.pack(pady=5)

    # Funkcija za čuvanje znamenitosti
    def save_landmark():
        name = name_entry.get()
        description = description_entry.get("1.0", "end-1c")  # Uzima tekst iz Text widgeta
        location = location_entry.get()
        image_url = image_url_entry.get()
        short_description = short_description_entry.get()

        if len(short_description) > 20:
            messagebox.showerror("Greška", "Kraći opis mora imati najviše 20 karaktera!")
            return
        
        if not name or not short_description or not description or not location or not image_url:
            messagebox.showerror("Greška", "Sva polja moraju biti popunjena!")
            return

        add_landmark(name, description, location, image_url, short_description)
        messagebox.showinfo("Uspeh", f"Znamenitost '{name}' je uspešno dodata!")

        # Resetovanje polja nakon uspešnog dodavanja znamenitosti
        name_entry.delete(0, 'end')  # Brisanje sadržaja iz Entry polja
        short_description_entry.delete(0, 'end')
        description_entry.delete("1.0", "end")  # Brisanje sadržaja iz Text polja
        location_entry.delete(0, 'end')
        image_url_entry.delete(0, 'end')

    # Dugme za čuvanje znamenitosti
    tk.Button(root, text="Sačuvaj znamenitost", command=save_landmark, font=("Arial", 12), bg="#4CAF50", fg="white", 
              width=20, height=2).pack(pady=10)

    # Dugme za povratak na Content Writer meni (Nazad)
    tk.Button(root, text="Nazad", command=lambda: content_writer_menu(user), font=("Arial", 12), bg="#d9534f", fg="white", 
              width=20, height=2).pack(pady=10)
 
def registered_user_menu(user):
    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text="Izaberite epohe i autore", font=("Arial", 14)).pack(pady=10)

    # Dugme za slanje zahteva da postane pisac sadržaja
    def send_request():
        c.execute("UPDATE users SET request_content_writer=1 WHERE id=?", (user[0],))
        conn.commit()
        messagebox.showinfo("Zahtev poslat", "Vaš zahtev da postanete pisac sadržaja je poslat administratoru.")
        request_button.pack_forget()  # Sakriva dugme nakon slanja zahteva

    # Provera da li je korisnik već poslao zahtev
    c.execute("SELECT request_content_writer FROM users WHERE id=?", (user[0],))
    request_status = c.fetchone()[0]

    if request_status == 0:
        request_button = tk.Button(root, text="Pošalji zahtev da postaneš pisac sadržaja", font=("Arial", 12), bg="#5cb85c", fg="white",
                                   width=50, height=2, command=send_request)
        request_button.pack(pady=10)


    # Lista epoha i autora
    epochs = ["Ranosrednjovekovna arhitektura (6-12. vek)", 
            "Raska skola (12-14. vek)", 
            "Moravska skola (14-15. vek)", 
            "Osmanski period (15-19. vek)", 
            "Barok i klasicizam (18-19. vek)", 
            "Neoromantizam i neobizantijski stil (19. vek - pocetak 20. veka)", 
            "Modernizam i medjuratna arhitektura (1918-1941)", 
            "Socijalisticki realizam i brutalizam (1945-1990)", 
            "Savremena arhitektura (1990 - danas)"]

    authors = ["Paja Jovanović", "Uroš Predić", "Ivan Meštrović", "Nadežda Petrović"]

    # Listbox za epohe
    tk.Label(root, text="Izaberite epohe", font=("Arial", 12)).pack()
    epoch_listbox = tk.Listbox(root, selectmode="multiple", font=("Arial", 12), height=8, width=50)
    for epoch in epochs:
        epoch_listbox.insert(tk.END, epoch)
    epoch_listbox.pack(pady=5)

    # Listbox za autore
    tk.Label(root, text="Izaberite autore", font=("Arial", 12)).pack()
    author_listbox = tk.Listbox(root, selectmode="multiple", font=("Arial", 12), height=5, width=50)
    for author in authors:
        author_listbox.insert(tk.END, author)
    author_listbox.pack(pady=5)

    # Dugme za prikazivanje znamenitosti
    tk.Button(root, text="Prikaži znamenitosti", font=("Arial", 12), bg="#4CAF50", fg="white", width=20, height=2,
              command=lambda: show_landmarks_page(user, [epochs[i] for i in epoch_listbox.curselection()], [authors[i] for i in author_listbox.curselection()])).pack(pady=10)
    
    # Dugme za logout na dnu
    tk.Button(root, text="Logout", command=start_page, font=("Arial", 12), bg="#d9534f", fg="white", width=30, height=2).pack(side="bottom", pady=20)

def show_landmarks_page(user, selected_epochs, selected_authors):
    landmarks = get_landmarks_by_epochs_and_authors(selected_epochs, selected_authors)

    # Ako nema znamenitosti, prikazujemo upozorenje, ali ne brišemo stranicu
    if not landmarks:
        messagebox.showwarning("Upozorenje", "Nema dostupnih znamenitosti za izabrane epohe i autore.")
        return  # Vraćamo se bez resetovanja stranice

    # Ako ima znamenitosti, nastavljamo sa prikazom nove stranice
    for widget in root.winfo_children():
        widget.destroy()

    selected_landmarks = []

    # Funkcija za ažuriranje pregleda odabranih znamenitosti
    def update_selected_landmarks_view():
        for widget in selected_landmarks_frame.winfo_children():
            widget.destroy()

        for landmark in selected_landmarks:
            label = tk.Label(selected_landmarks_frame, text=f"{landmark[1]} - {landmark[5]}")
            label.pack(anchor="w")

            # Dugme za uklanjanje znamenitosti iz rute
            remove_btn = tk.Button(selected_landmarks_frame, text="Izbaci", command=lambda l=landmark: remove_landmark(l))
            remove_btn.pack(anchor="w", padx=5)

    # Funkcija za dodavanje znamenitosti u rutu
    def select_landmark(landmark):
        if landmark not in selected_landmarks:
            selected_landmarks.append(landmark)
            update_selected_landmarks_view()
        else:
            messagebox.showwarning("Upozorenje", f"Znamenitost {landmark[1]} je već dodata.")

    # Funkcija za uklanjanje znamenitosti iz rute
    def remove_landmark(landmark):
        if landmark in selected_landmarks:
            selected_landmarks.remove(landmark)
            update_selected_landmarks_view()

    # Prikazivanje svih znamenitosti u dropdown meniju
    tk.Label(root, text="Izaberite znamenitost za kreiranje rute", font=("Arial", 14)).pack(pady=10)

    selected_landmark_var = tk.StringVar()
    selected_landmark_var.set("Izaberite znamenitost")

    landmark_options = [f"{landmark[1]} - {landmark[5]}" for landmark in landmarks]  # Ime i opis
    dropdown_frame = tk.Frame(root)
    dropdown_frame.pack(pady=10)

    dropdown = tk.OptionMenu(dropdown_frame, selected_landmark_var, *landmark_options)
    dropdown.config(font=("Arial", 12), width=25, bg="#f0f0f0", fg="black")
    dropdown.pack(pady=5)

    # Okvir za prikaz odabranih znamenitosti
    selected_landmarks_frame = tk.Frame(root)
    selected_landmarks_frame.pack(side="right", fill="y", padx=10)

    # Dodavanje checkboxova s leve strane
    checkbox_frame = tk.Frame(root)
    checkbox_frame.pack(side="left", fill="y", padx=10)

    tk.Label(checkbox_frame, text="Opcije za PDF", font=("Arial", 12)).pack(anchor="w")

    short_desc_var = tk.IntVar()
    long_desc_var = tk.IntVar()
    epoch_desc_var = tk.IntVar()

    tk.Checkbutton(checkbox_frame, text="Kraći opis", variable=short_desc_var, font=("Arial", 12)).pack(anchor="w")
    tk.Checkbutton(checkbox_frame, text="Duži opis", variable=long_desc_var, font=("Arial", 12)).pack(anchor="w")
    tk.Checkbutton(checkbox_frame, text="Opis epohe", variable=epoch_desc_var, font=("Arial", 12)).pack(anchor="w")

    # Dodavanje dugmadi
    tk.Button(root, text="Dodaj znamenitost", font=("Arial", 12), bg="#4CAF50", fg="white", width=20, height=2,
              command=lambda: select_landmark(next((landmark for landmark in landmarks if selected_landmark_var.get() == f"{landmark[1]} - {landmark[5]}"), None))).pack(pady=5)

    # Dodavanje dugmeta za kreiranje PDF-a sa odabranim opcijama
    tk.Button(root, text="Kreiraj rutu i PDF", font=("Arial", 12), bg="#008CBA", fg="white", width=20, height=2,
              command=lambda: generate_route_and_pdf(selected_landmarks, short_desc_var.get(), long_desc_var.get(), epoch_desc_var.get())).pack(pady=5)

    tk.Button(root, text="Sačuvaj rutu", font=("Arial", 12), bg="#FFA500", fg="white", width=20, height=2,
              command=lambda: save_route_prompt(user, selected_landmarks)).pack(pady=5)

    tk.Button(root, text="Učitaj sačuvanu rutu", font=("Arial", 12), bg="#f0ad4e", fg="white", width=20, height=2,
              command=lambda: load_saved_route(user)).pack(pady=5)

    # Dugme za povratak na izbor epoha i autora
    tk.Button(root, text="Nazad", font=("Arial", 12), bg="#d9534f", fg="white", width=20, height=2,
              command=lambda: registered_user_menu(user)).pack(side="bottom", pady=20)

# Funkcija za preuzimanje znamenitosti na osnovu više epoha i autora
def get_landmarks_by_epochs_and_authors(epochs, authors):
    placeholders_epochs = ', '.join('?' for _ in epochs)
    placeholders_authors = ', '.join('?' for _ in authors)
    
    query = f"SELECT * FROM landmarks WHERE epoch IN ({placeholders_epochs}) OR name IN ({placeholders_authors})"
    c.execute(query, tuple(epochs + authors))
    return c.fetchall()
 
# Funkcija za preuzimanje znamenitosti na osnovu odabranih interesa
def get_landmarks_by_interest(interests):
    # Pretvaramo interese u SQL upit
    placeholders = ', '.join('?' for _ in interests)
    query = f"SELECT * FROM landmarks WHERE short_description IN ({placeholders}) OR name IN ({placeholders})"
    c.execute(query, interests + interests)  # Koristimo interese za pretragu
    return c.fetchall()


# Funkcija za prikazivanje menija za logovanje
# Funkcija za prikazivanje menija za logovanje
def login_menu():
    for widget in root.winfo_children():
        widget.destroy()

    # Podesimo naslov sa većim fontom i marginama
    tk.Label(root, text="Prijavi se", font=("Arial", 16), pady=20).pack()

    # Podesimo labelu i unos za korisničko ime
    tk.Label(root, text="Korisničko ime:", font=("Arial", 12)).pack(pady=5)
    username_entry = tk.Entry(root, font=("Arial", 12), width=30)
    username_entry.pack(pady=5)

    # Podesimo labelu i unos za lozinku
    tk.Label(root, text="Lozinka:", font=("Arial", 12)).pack(pady=5)
    password_entry = tk.Entry(root, show="*", font=("Arial", 12), width=30)
    password_entry.pack(pady=5)

    # Funkcija za pokušaj logovanja
    def try_login():
        username = username_entry.get()
        password = password_entry.get()
        user = login_user(username, password)
        if user:
            messagebox.showinfo("Uspeh", f"Uspešno ste prijavljeni kao {user[1]} ({user[4]})")
            if user[4] == "admin":
                admin_menu(user)
            elif user[4] == "content_writer":
                content_writer_menu(user)
            elif user[4] == "registered_user":
                registered_user_menu(user)
        else:
            messagebox.showerror("Greška", "Pogrešno korisničko ime ili lozinka.")

    # Dugme za prijavu sa stilom
    tk.Button(root, text="Prijavi se", command=try_login, font=("Arial", 12), bg="#4CAF50", fg="white",
              width=20, height=2).pack(pady=20)

    # Dugme "Nazad" postavljeno na dno sa stilom
    tk.Button(root, text="Nazad", command=start_page, font=("Arial", 12), bg="#d9534f", fg="white",
              width=20, height=2).pack(side="bottom", pady=20)
# Funkcija za prikazivanje menija za registraciju
def register_menu():
    for widget in root.winfo_children():
        widget.destroy()

    # Naslov sa većim fontom i marginom
    tk.Label(root, text="Registruj se", font=("Arial", 16), pady=20).pack()

    # Polje za korisničko ime
    tk.Label(root, text="Korisničko ime:", font=("Arial", 12)).pack(pady=5)
    username_entry = tk.Entry(root, font=("Arial", 12), width=30)
    username_entry.pack(pady=5)

    # Polje za email
    tk.Label(root, text="Email:", font=("Arial", 12)).pack(pady=5)
    email_entry = tk.Entry(root, font=("Arial", 12), width=30)
    email_entry.pack(pady=5)

    # Polje za lozinku
    tk.Label(root, text="Lozinka:", font=("Arial", 12)).pack(pady=5)
    password_entry = tk.Entry(root, show="*", font=("Arial", 12), width=30)
    password_entry.pack(pady=5)

    # Funkcija za pokušaj registracije
    def try_register():
        username = username_entry.get()
        email = email_entry.get()
        password = password_entry.get()
        role = "registered_user"  # Svi korisnici se registruju kao obicni korisnici
        register_user(username, email, password, role)
        messagebox.showinfo("Uspeh", f"Uspešno ste registrovani kao {username} (običan korisnik)")
        start_page()  # Vrati na početnu stranicu nakon registracije

    # Dugme za registraciju sa stilom
    tk.Button(root, text="Registruj se", command=try_register, font=("Arial", 12), bg="#4CAF50", fg="white",
              width=20, height=2).pack(pady=20)

    # Dugme "Logout" (ranije "Nazad") postavljeno na dno sa stilom
    tk.Button(root, text="Logout", command=start_page, font=("Arial", 12), bg="#d9534f", fg="white",
              width=20, height=2).pack(side="bottom", pady=20)
def admin_menu(user):
    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text="Administrativni meni", font=("Arial", 16)).pack(pady=10)

    # Funkcija za preuzimanje korisnika koji su poslali zahtev
    def get_users_for_content_writer():
        c.execute("SELECT id, username FROM users WHERE request_content_writer=1 AND role='registered_user'")
        return c.fetchall()

    # Preuzmi listu korisnika sa zahtevima
    users = get_users_for_content_writer()

    if not users:
        tk.Label(root, text="Nema zahteva za pisca sadržaja.", font=("Arial", 12)).pack(pady=10)
        return 

    tk.Label(root, text="Izaberite korisnika koji je poslao zahtev:", font=("Arial", 12)).pack()

    selected_user_var = tk.StringVar()
    selected_user_var.set("Izaberite korisnika")

    # Dropdown za korisnike
    user_options = [f"{user[1]}" for user in users]
    dropdown = tk.OptionMenu(root, selected_user_var, *user_options)
    dropdown.pack(pady=10)

    # Funkcija za odobravanje zahteva
    def approve_user():
        selected_username = selected_user_var.get()
        if selected_username != "Izaberite korisnika":
            c.execute("UPDATE users SET role='content_writer', request_content_writer=0 WHERE username=?", (selected_username,))
            conn.commit()
            messagebox.showinfo("Uspeh", f"Korisnik {selected_username} je sada pisac sadržaja.")
            # Ukloni korisnika iz dropdown liste bez resetovanja stranice
            users.remove(next(user for user in users if user[1] == selected_username))
            if not users:
                tk.Label(root, text="Nema više zahteva za pisca sadržaja.", font=("Arial", 12)).pack(pady=10)
                dropdown.pack_forget()  # Sakrij dropdown ako nema više korisnika sa zahtevima
        else:
            messagebox.showerror("Greška", "Morate izabrati korisnika.")

    tk.Button(root, text="Odobri korisnika", command=approve_user, font=("Arial", 12), bg="#4CAF50", fg="white",
              width=20, height=2).pack(pady=10)

    # Dugme za logout na dnu
    tk.Button(root, text="Logout", command=start_page, font=("Arial", 12), bg="#d9534f", fg="white", width=30, height=2).pack(side="bottom", pady=20)

# Funkcija za preuzimanje svih znamenitosti iz baze
def get_all_landmarks():
    c.execute("SELECT * FROM landmarks")
    return c.fetchall()

# Funkcija za početnu stranicu
def start_page():
    for widget in root.winfo_children():
        widget.destroy()

    # Naslov sa velikim fontom
    tk.Label(root, text="Dobrodošli u aplikaciju", font=("Arial", 18), pady=20).pack()

    # Stilizovana dugmad za različite opcije
    tk.Button(root, text="Prijavi se", command=login_menu, font=("Arial", 12), bg="#5cb85c", fg="white", width=20, height=2).pack(pady=10)
    tk.Button(root, text="Registruj se", command=register_menu, font=("Arial", 12), bg="#0275d8", fg="white", width=20, height=2).pack(pady=10)
    tk.Button(root, text="Uđi kao gost", command=guest_menu, font=("Arial", 12), bg="#f0ad4e", fg="white", width=20, height=2).pack(pady=10)

    # Dugme za izlaz (ako je potrebno)
    tk.Button(root, text="Izlaz", command=root.quit, font=("Arial", 12), bg="#d9534f", fg="white", width=20, height=2).pack(side="bottom", pady=20)
def guest_menu():
    for widget in root.winfo_children():
        widget.destroy()

    tk.Label(root, text="Izaberite znamenitost za kreiranje rute", font=("Arial", 14)).pack(pady=10)

    landmarks = get_all_landmarks()  # Preuzimamo sve znamenitosti

    if not landmarks:
        messagebox.showwarning("Upozorenje", "Nema dostupnih znamenitosti.")
        return

    selected_landmarks = []

    # Funkcija za ažuriranje pregleda odabranih znamenitosti
    def update_selected_landmarks_view():
        for widget in selected_landmarks_frame.winfo_children():
            widget.destroy()

        for landmark in selected_landmarks:
            label = tk.Label(selected_landmarks_frame, text=f"{landmark[1]} - {landmark[5]}")
            label.pack(anchor="w")

            # Dugme za uklanjanje znamenitosti iz rute
            remove_btn = tk.Button(selected_landmarks_frame, text="Izbaci", command=lambda l=landmark: remove_landmark(l))
            remove_btn.pack(anchor="w", padx=5)

    # Funkcija za dodavanje znamenitosti u rutu
    def select_landmark(landmark):
        if landmark not in selected_landmarks:
            selected_landmarks.append(landmark)
            update_selected_landmarks_view()
        else:
            messagebox.showwarning("Upozorenje", f"Znamenitost {landmark[1]} je već dodata.")

    # Funkcija za uklanjanje znamenitosti iz rute
    def remove_landmark(landmark):
        if landmark in selected_landmarks:
            selected_landmarks.remove(landmark)
            update_selected_landmarks_view()

    # Kreiraj OptionMenu za izbor znamenitosti
    tk.Label(root, text="Izaberite znamenitost:", font=("Arial", 12)).pack()
    selected_landmark_var = tk.StringVar()
    selected_landmark_var.set("Izaberite znamenitost")  # Podrazumevana prva znamenitost

    landmark_options = [f"{landmark[1]} - {landmark[5]}" for landmark in landmarks]  # Ime i kraći opis
    dropdown_frame = tk.Frame(root)
    dropdown_frame.pack(pady=10)

    dropdown = tk.OptionMenu(dropdown_frame, selected_landmark_var, *landmark_options)
    dropdown.config(font=("Arial", 12), width=25, bg="#f0f0f0", fg="black")
    dropdown.pack(pady=5)

    # Okvir za prikaz odabranih znamenitosti
    selected_landmarks_frame = tk.Frame(root)
    selected_landmarks_frame.pack(side="right", fill="y", padx=10)

    # Dodavanje checkboxova s leve strane
    checkbox_frame = tk.Frame(root)
    checkbox_frame.pack(side="left", fill="y", padx=10)

    tk.Label(checkbox_frame, text="Opcije za PDF", font=("Arial", 12)).pack(anchor="w")

    short_desc_var = tk.IntVar()
    long_desc_var = tk.IntVar()
    epoch_desc_var = tk.IntVar()

    tk.Checkbutton(checkbox_frame, text="Kraći opis", variable=short_desc_var, font=("Arial", 12)).pack(anchor="w")
    tk.Checkbutton(checkbox_frame, text="Duži opis", variable=long_desc_var, font=("Arial", 12)).pack(anchor="w")
    tk.Checkbutton(checkbox_frame, text="Opis epohe", variable=epoch_desc_var, font=("Arial", 12)).pack(anchor="w")

    # Dodavanje dugmadi
    tk.Button(root, text="Dodaj znamenitost", font=("Arial", 12), bg="#4CAF50", fg="white", width=20, height=2,
              command=lambda: select_landmark(next((landmark for landmark in landmarks if selected_landmark_var.get() == f"{landmark[1]} - {landmark[5]}"), None))).pack(pady=5)

    # Dodavanje dugmeta za kreiranje PDF-a sa odabranim opcijama
    tk.Button(root, text="Kreiraj rutu i PDF", font=("Arial", 12), bg="#008CBA", fg="white", width=20, height=2,
              command=lambda: generate_route_and_pdf(selected_landmarks, short_desc_var.get(), long_desc_var.get(), epoch_desc_var.get())).pack(pady=5)

    # Dugme za povratak na početnu stranicu (logout)
    tk.Button(root, text="Logout", font=("Arial", 12), bg="#d9534f", fg="white", width=20, height=2,
              command=start_page).pack(side="bottom", pady=20)



# Kreiranje glavnog GUI prozora
root = tk.Tk()
root.title("Planer rute")
root.geometry("600x600")
# Pokretanje početne stranice
start_page()

# Pokretanje glavne Tkinter petlje
root.mainloop()