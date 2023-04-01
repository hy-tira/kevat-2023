---
title: Vilppiä Tirassa
hidden: true
---

# Vilppiä Tirassa

Kevään 2023 Tiran I-osan arvostelussa huomattiin, että monet kurssin opiskelijat ovat lähettäneet tehtäviin ratkaisuja, jotka eivät vaikuta itsenäisesti laadituilta.
Tämä raportti kuvaa, millaista vilppiä Tirassa epäillään ja miten laajalta ilmiö vaikuttaa.

## Taustaa

Tira järjestetään MOOC-kurssina, jossa arvostelu perustuu kurssin aikana suoritettaviin tehtäviin.
Tehtävät palautetaan CSES-järjestelmään, joka arvostelee ne automaattisesti.
Kurssilla ei ole tenttiä, vaan arvostelu perustuu pelkästään tehtäviin.

Kurssisivustolla on ilmoitettu [kurssin pelisäännöt](pelisaannot.html),
jotka määrittävät, että kurssilla palautettavat ratkaisut tulee tuottaa itsenäisesti.
Tehtävistä saa keskustella muiden kanssa ja tehtävissä saa hyödyntää nettiä,
mutta ratkaisut tulee kirjoittaa alusta alkaen itse.

Tirassa on havaittu edellisinä vuosina jonkin verran vilppiä, mutta tänä keväänä ilmiö vaikuttaa selvästi aiempaa laajemmalta.

## Paljonko vilppiä esiintyy?

Kevään 2023 Tiran I-osaan osallistui 366 opiskelijaa. Kurssin arvioinnin aikana havaittiin X opiskelijaa,
joita epäillään vilpistä. Niinpä X % kurssin opiskelijoista epäillään vilpistä.

Näissä epäilyissä opiskelija on lähettänyt ratkaisun, joka selkeästi ei vaikuta itsenäisesti laaditulta,
joten kyse on luultavasti todellisesta vilpistä.
Yleinen tilanne on, että opiskelija on lähettänyt ratkaisun, joka on lähes sama kuin tehtävän malliratkaisu.

Kurssin luennoija ottaa yhteyttä vilpistä epäiltyyn opiskelijaan ja pyytää häneltä selitystä asiaan.
On myös mahdollista, että epäily vilpistä osoittautuu aiheettomaksi.

## Miten vilppiä havaitaan?

Tarkastellaan esimerkkinä kurssin viimeisen viikon tehtävää [Minimikeko](https://cses.fi/tira23k/task/2717).
Tehtävän malliratkaisuna on seuraava koodi:

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

Tehtävään liittyvää vilppiä voidaan havaita etsimällä ratkaisuja, jotka ovat lähellä malliratkaisua.
Seuraavassa on kolme esimerkkiä opiskelijoiden ratkaisuista, joita epäillään vilpistä.

### Esimerkki 1

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

Tämä vaikuttaa olevan malliratkaisun kopio,
jossa jokainen muuttujan nimi on käännetty englannista suomeksi.
Tavoitteena on ehkä ollut kätkeä vilppi vaihtamalla muuttujien nimiä.

### Esimerkki 2

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
Muuttujien nimien vaihtamisen lisäksi esimerkiksi
rivien järjestystä on muutettu,
for-silmukka on korvattu while-silmukalla ja
if-rakenne on jaettu kahteen osaan.

### Esimerkki 3

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
    
## Miksi vilppiä esiintyy?

Mahdollisia syitä vilppiin ovat:

* Opiskelijoilla on käytössä tehtävien malliratkaisuja edellisiltä kursseilta.
* Osaan tehtävistä voi löytää valmiita ratkaisuja netistä.
* Saattaa tulla vaikutelma, ettei kukaan käy läpi tehtävien lähetyksiä.
* Vilppi tehtävissä saattaa tuntua hyväksyttävämmältä kuin tuntuisi vilppi tentissä.
* Opiskelijoille ei ole selvää, mikä on vilppiä.
* Tiran aiheet eivät kiinnosta kaikkia tai tuntuvat liian vaikeilta, jolloin ei tunnu mielekkäältä käyttää aikaa kurssin tehtäviin.

## Miten eteenpäin?

Suuri vilpin määrä täytyy ottaa huomioon Tiran tulevaisuuden suunnittelussa. Onko mielekästä järjestää kurssia ilman valvottuja tenttejä?

Kurssin tiedotusta voidaan parantaa niin, että kurssin pelisäännöt tulevat selvemmin esille.

Vilppi ei ole ongelma vain Tirassa, vaan sitä tapahtuu myös muilla kursseilla. Tätä asiaa saattaisi olla syytä käsitellä yleisemmin tietojenkäsittelytieteen opetuksessa.
