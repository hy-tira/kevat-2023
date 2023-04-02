---
title: Vilppiä Tirassa
hidden: true
---

# Vilppiä Tirassa

Kevään 2023 Tiran I-osan arvostelussa huomattiin, että monet kurssin opiskelijat ovat lähettäneet tehtäviin ratkaisuja, jotka eivät vaikuta itsenäisesti laadituilta.
Tämä raportti kuvaa, millaista vilppiä Tirassa epäillään ja miten laajalta ilmiö vaikuttaa.

## Taustaa

Kevään 2023 Tira on järjestetty MOOC-kurssina, jossa arvostelu perustuu kurssin tehtäviin.
Tehtävät palautetaan CSES-järjestelmään, joka arvostelee ne automaattisesti.
Kurssilla ei ole tenttiä, vaan arvostelu perustuu pelkästään tehtäviin.

Kurssisivustolla on ilmoitettu [kurssin pelisäännöt](pelisaannot.html),
jotka määrittävät, että kurssilla palautettavat ratkaisut tulee tuottaa itsenäisesti.
Tehtävistä saa keskustella muiden kanssa ja tehtävissä saa hyödyntää nettiä,
mutta ratkaisut tulee kirjoittaa alusta alkaen itse.
Jos ratkaisu perustuu netistä löydettyyn ideaan, sen yhteydessä tulee ilmoittaa lähde.

Tirassa on havaittu edellisinä vuosina jonkin verran vilppiä, mutta tänä keväänä ilmiö vaikuttaa aiempaa laajemmalta.

## Paljonko vilppiä esiintyy?

Kevään 2023 Tiran I-osaan osallistui 366 opiskelijaa. Kurssin arvioinnin aikana havaittiin X opiskelijaa,
joita epäillään vilpistä. Niinpä X % kurssin opiskelijoista epäillään vilpistä.

Näissä epäilyissä opiskelija on lähettänyt ratkaisun, joka selkeästi ei vaikuta itsenäisesti laaditulta,
joten kyse on luultavasti todellisesta vilpistä.
On kuitenkin mahdollista, että epäily osoittautuu aiheettomaksi.

## Miten vilppiä havaitaan?

Vilppiä voidaan havaita etsimällä ratkaisuja, jotka eivät vaikuta itsenäisesti laadituilta. Yleisiä tilanteita ovat, että opiskelijan ratkaisu muistuttaa malliratkaisua tai kaksi opiskelijaa ovat lähettäneet samanlaisen ratkaisun.

Ratkaisujen vertailussa täytyy ottaa huomioon, että ratkaisujen välillä saattaa olla pieniä eroja. Esimerkiksi koodin muuttujien nimien vaihtaminen on yleinen tapa koettaa kätkeä vilppiä. Usein koodien rakenteessa on muitakin pieniä eroja.

Vilppiä voidaan havaita myös siitä, että opiskelija on lähettänyt ratkaisuja poikkeuksellisella tavalla: esimerkiksi opiskelija on saanut paljon tehtäviä ensimmäisellä yrityksellä oikein tai eri tehtävien ratkaisujen lähetysajat ovat hyvin lähellä toisiaan.

### Esimerkki: vilppi malliratkaisun avulla

Tarkastellaan Tiran tehtävää [Minimikeko](https://cses.fi/tira23k/task/2717), jonka malliratkaisu on seuraava:

```python
def count(n, k):
    size = (1+2**8) * [0]
    path = (1+2**8) * [0]
    result = 0
    for i in range(n, 0, -1):
        size[i] = 1 + size[2*i] + size[2*i+1]
    for i in range(1, n+1):
        path[i] = 1 + path[i//2]
        if size[i] <= n-k+1 and path[i] <= k:
            result += 1
    return result
```

Seuraavassa on kolme esimerkkiä opiskelijoiden ratkaisuista, joita epäillään vilpistä.

**Ratkaisu 1**

```python
def count(n, k):
    koko = (1+2**8) * [0]
    polku = (1+2**8) * [0]
    vastaus = 0
    for i in range(n, 0, -1):
        koko[i] = 1 + koko[2*i] + koko[2*i+1]
    for i in range(1, n+1):
        polku[i] = 1 + polku[i//2]
        if koko[i] <= n-k+1 and polku[i] <= k:
            vastaus += 1
    return vastaus
```

Tämä koodi vastaa muuten täysin malliratkaisua, mutta jokaisen muuttujan nimi on käännetty englannista suomeksi.

**Ratkaisu 2**

```python
def count(n, k):
 
    luvut = n
    kKpl = 0
    koko = [0] * (2**8 + 1)
    list = [0] * (2**8 + 1)
 
    
    for i in range(luvut,0,-1):
        
        koko[i] = 1 + koko[i+i] + koko[i+i+1]
        
        
    i = 1
 
    while i < luvut +1:
        indeksi = i // 2
        list[i] = list[indeksi] + 1
 
        if koko[i] <= luvut-k+1:
            if list[i] <= k:
                kKpl += 1
 
        i += 1
 
    return kKpl
```

Tässä vaikuttaa, että malliratkaisuun on tehty useita pieniä muutoksia.
Muuttujien nimien vaihtamisen lisäksi rivien järjestystä on muutettu, for-silmukka on korvattu while-silmukalla ja
if-rakenne on jaettu kahteen osaan.

**Ratkaisu 3**

```python
def count(n, k):
    kohtia=0
    lista=[]
    for i in range(1000):
        lista.append(0)
    apu=lista[:]
    #käydään listaa läpi vikasta ekaan jäseneen
    #solmun vas lapsi kohdassa 2k ja oik lapsi 2k+1
    #solmun vanhempi on k/2 kohdassa
    for i in range(n,0,-1):
        lista[i]=lista[2*i]+lista[i*2+1]+1
 
    for i in range(1,n+1):
        apu[i]=apu[int(i/2)]+1
        if n-k+1>=lista[i] and k>=apu[i]:
            kohtia+=1
    return kohtia
```

Myös tässä vaikuttaa, että malliratkaisuun on tehty joukko pieniä muutoksia.
Suurin ero malliratkaisuun verrattuna on, että listat luodaan eri tavalla.
Koodissa on myös kommentti, joka ei kuitenkaan selitä juurikaan
ratkaisun ideaa.

## Mitä vilpistä seuraa?

Kurssin luennoija ottaa yhteyttä vilpistä epäiltyyn opiskelijaan ja pyytää häneltä selitystä asiaan.
Jos epäily vilpistä on aiheellinen, opiskelija menettää pisteet tehtävästä tai tehtävistä ja asiasta ilmoitetaan koulutusohjelman johtajalle.

## Miksi vilppiä esiintyy?

Osalla opiskelijoista on käytössä tehtävien malliratkaisuja aiemmilta kursseilta. Tirassa ei ole mahdollista laatia uusia tehtäviä joka kurssille, ja tähän asti käytäntönä on ollut julkaista malliratkaisut deadlinen jälkeen. Lisäksi osaan tehtävistä voi löytää valmiita ratkaisuja netistä.

Kun kurssin tehtävät arvioidaan automaattisesti, saattaa tulla vaikutelma, ettei kukaan ihminen käy läpi lähetyksiä. Tämän vuoksi voi tuntua siltä, ettei ole riskiä jäädä kiinni. Vilppi tehtävissä saattaa myös tuntua hyväksyttävämmältä kuin esimerkiksi vilppi tentissä.

Vaikka kurssisivustolla on julkaistu kurssin pelisäännöt, osa opiskelijoista ei ole välttämättä huomannut niitä tai lukenut niitä huolellisesti. Niinpä kaikille opiskelijoille ei ole välttämättä selvää, mikä on vilppiä.

Tiran aiheet eivät kiinnosta kaikkia opiskelijoita tai tuntuvat liian vaikeilta, jolloin ei tunnu mielekkäältä käyttää aikaa kurssin tehtäviin. Opiskelijan esitiedot saattavat olla myös puutteelliset kurssin suorittamiseen.

## Miten estää vilppiä?

Tehokas keino estää malliratkaisuihin liittyvää vilppiä on uudistaa jatkuvasti kurssin tehtäviä. Tämä on mahdollista mutta aiheuttaa paljon työtä kurssin opettajille. Lisäksi olisi mahdollista olla julkaisematta malliratkaisuja tehtäviin, mikä kuitenkin haittaisi oppimista.

Tehtävien laadinnassa tulisi pyrkiä siihen, että tehtävien ratkaisuja ei löydy suoraan netistä. Netistä löytyy kuitenkin ratkaisuja todella moniin tehtäviin, ja on käytännössä vaikeaa laatia kurssille sopivia tehtäviä, joihin liittyen ei löydy tietoa netistä.

Tiran formaattia olisi mahdollista muuttaa niin, että keskeisenä osana suorituksessa olisi valvottu tentti. Tehtäviin perustuva formaatti on kuitenkin tuntunut paremmalta, koska tenttitilanne ei tunnu soveltuvan hyvin mittaamaan kykyä suunnitella algoritmeja. Lisäksi valvotun tentin järjestäminen Avoimen yliopiston opiskelijoille olisi hankalaa.

Kurssin tiedotusta on mahdollista parantaa niin, että kurssin pelisäännöt tulevat selvemmin esille. Esimerkiksi pelisäännöt voisivat tulla näkyviin ennen ensimmäisen tehtävän lähettämistä CSES:ssä, jotta kurssin opiskelijat huomaisivat ne todennäköisemmin.

Kurssin materiaalia ja tehtäviä on mahdollista parantaa niin, että materiaali tukee paremmin tehtäviä. Kurssin materiaaliin on tulossa lisää esimerkkejä algoritmien suunnitteluun liittyen. Tämä toivottavasti vähentää tarvetta vilppiin. Tiran aihepiiriä ei kuitenkaan voi muuttaa ja on ymmärrettävää, ettei Tira tule koskaan olemaan kaikkien lempikurssi.

## Miten hyvin vilppi huomataan?

Vilppiä ei ole mahdollista huomata kaikissa tilanteissa. Esimerkiksi jos tehtävän ratkaisu on lyhyt koodi, on mahdollista, että opiskelija päätyy itsenäisesti samanlaiseen ratkaisuun kuin malliratkaisu tai kaksi opiskelijaa päätyy samanlaiseen ratkaisuun.

Lisäksi on mahdollista, että joku toinen kurssin ulkopuolinen henkilö laatii ratkaisuja opiskelijan puolesta. Tällaista vilppiä ei yleensä pysty havaitsemaan, koska samanlaista koodia ei löydy muualta kurssin lähetyksistä.

Havaitun vilpin lisäksi on luultavasti muutakin esimerkiksi yllä olevan kaltaista vilppiä, mutta on vaikeaa arvioida, miten paljon sitä esiintyy.

## Esiintyykö vilppiä muilla kursseilla?

Vilppiä tapahtuu Tiran lisäksi muillakin kursseilla. Vaihtelee kurssista ja toteutuskerrasta riippuen, paljonko käytetään aikaa opiskelijoiden ratkaisujen läpikäyntiin. Tämä on asia, josta olisi hyvä keskustella enemmänkin tietojenkäsittelytieteen opetuksessa ja erityisesti MOOC-kurssien järjestämiseen liittyen.

## Miten ChatGPT vaikuttaa asiaan?

Tiran ja muiden kurssien tulevaisuudessa täytyy ottaa myös huomioon, että ChatGPT pystyy antamaan ratkaisuja moniin ohjelmointitehtäviin.

### Esimerkki ChatGPT:n käyttämisestä Tirassa

Koetetaan ratkaista Tiran tehtävä [Robotin reitti](https://cses.fi/tira23k/task/2682) ChatGPT:n avulla. Tässä ChatGPT:lle annetaan suoraan CSES:stä kopioitu Tiran tehtävänanto.

**Syöte ChatGPT:lle**

Robotti on alussa ruudussa (0,0). Tämän jälkeen robotti liikkuu annetun liikesarjan mukaisesti askeleen kerrallaan. Liikesarja muodostuu merkeistä U (up), D (down), L (left) ja R (right). Monessako eri ruudussa robotti käy yhteensä?

Voit olettaa, että liikesarjassa on enintään 105 komentoa.

Toteuta tiedostoon robot.py funktio count, jolle annetaan robotin liikesarja ja joka ilmoittaa eri ruutujen määrän.

**Vastaus ChatGPT:ltä**

Tässä on toteutus Python-kielellä:

```python
def count(moves):
    visited = set()
    x, y = 0, 0
    visited.add((x, y))
    for move in moves:
        if move == 'U':
            y += 1
        elif move == 'D':
            y -= 1
        elif move == 'L':
            x -= 1
        elif move == 'R':
            x += 1
        visited.add((x, y))
    return len(visited)
```

Funktio count ottaa parametrinaan robotin liikesarjan moves. Se käyttää Pythonin sisäänrakennettua set-rakennetta pitääkseen kirjaa eri ruuduista, joissa robotti käy. Alussa robotti on ruudussa (0, 0), joten lisäämme tämän ruudun visited-joukkoon.

Tämän jälkeen käymme läpi jokaisen liikkeen liikesarjasta moves. Jos liike on 'U', liikumme yhden askeleen ylöspäin muuttamalla y-koordinaattia yhdellä. 'D'-liike vastaavasti vähentää y-koordinaattia yhdellä, 'L' vähentää x-koordinaattia yhdellä ja 'R' lisää x-koordinaattia yhdellä. Tämän jälkeen lisäämme uuden ruudun visited-joukkoon.

Lopuksi palautamme visited-joukon koon, joka kertoo eri ruutujen määrän, joissa robotti kävi.

**Kommentti**

ChatGPT:n antaman koodin voi lähettää suoraan CSES:ään, ja se läpäisee kaikki testit. Koodista ei ole mahdollista havaita, ettei se ole opiskelijan itse tuottama.

Huomaa, että kopioidussa tehtävänannossa rajaksi tuli 105 eikä $$10^5$$, koska potenssimerkintä katosi kopioinnin yhteydessä. Tämä ei kuitenkaan haitannut tässä tapauksessa.

ChatGPT:ltä voidaan pyytää vielä muutoksia koodiin:

**Syöte ChatGPT:lle**

Muuta koodia niin, että siinä on kommentit suomeksi sekä koodi käyttää while-silmukkaa for-silmukan sijasta.

**Vastaus ChatGPT:ltä**

Tässä on päivitetty toteutus, joka käyttää while-silmukkaa for-silmukan sijasta ja sisältää kommentit suomeksi:

```python
def count(moves):
    visited = set()  # Alustetaan joukko, johon tallennetaan käydyt ruudut
    x, y = 0, 0  # Alustetaan robotti ruutuun (0, 0)
    visited.add((x, y))  # Lisätään lähtöruutu joukkoon
    
    i = 0  # Alustetaan liikesarjan indeksi
    while i < len(moves):  # Käydään läpi liikesarja
        move = moves[i]
        
        # Päivitetään robottia vastaavan liikkeen mukaisesti
        if move == 'U':
            y += 1
        elif move == 'D':
            y -= 1
        elif move == 'L':
            x -= 1
        elif move == 'R':
            x += 1
            
        visited.add((x, y))  # Lisätään uusi ruutu joukkoon
        
        i += 1  # Siirrytään seuraavaan liikkeeseen
        
    return len(visited)  # Palautetaan käytyjen ruutujen määrä
```

Kuten aiemmassa toteutuksessa, funktio count ottaa parametrinaan robotin liikesarjan moves ja käyttää joukkoa visited pitääkseen kirjaa eri ruuduista, joissa robotti käy.

Sen sijaan, että käytettäisiin for-silmukkaa liikesarjan läpikäymiseen, tässä käytetään while-silmukkaa. Aluksi asetetaan muuttuja i arvoon 0, joka toimii liikesarjan indeksinä. Silmukassa käydään läpi liikesarja, kunnes i saavuttaa liikesarjan pituuden.

Jokaisessa silmukan läpikäynnissä otetaan moves-listalta i:n kohdalta liike move. Tämän jälkeen päivitetään robottia vastaavan liikkeen mukaisesti, lisätään uusi ruutu visited-joukkoon ja siirrytään seuraavaan liikkeeseen kasvattamalla indeksiä i yhdellä.

Lopuksi palautetaan visited-joukon koko, joka kertoo eri ruutujen määrän, joissa robotti kävi.

**Kommentti**

Tästä näkee, että ChatGPT soveltuu hyvin myös olemassa olevan koodin muokkaamiseen. Myös muokattu versio toimii suoraan CSES:ssä ja läpäisee kaikki testit.
