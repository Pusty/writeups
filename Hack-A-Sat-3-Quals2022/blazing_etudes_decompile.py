# list of all files

files = """alarming_shuffle, alarming_study, anxious_ball, anxious_concerto, anxious_jitterbug, anxious_mixer, anxious_polka,
 baleful_concerto, baleful_dance, baleful_jig, baleful_masquerade, baleful_prom, baleful_scale,
baleful_shimmy, baleful_shuffle, baleful_study, baleful_twist, bleak_canon, bleak_composition, bleak_concerto,
bleak_dance, bleak_etude, bleak_shuffle, bleak_waltz, dire_ball, dire_boogey, dire_etude, dire_jitterbug,
dire_masquerade, dire_reception, dire_shimmy, dire_twist, dire_waltz, direful_bop, direful_composition, direful_dirge,
direful_drill, direful_etude, direful_gavotte, direful_jig, direful_jitterbug, doomy_dirge, doomy_mixer, doomy_waltz,
dreary_arrangement, dreary_bop, dreary_formal, dreary_reception, dreary_scale, fearful_canon, fearful_form,
fearful_gavotte, fearful_piece, fearful_shimmy, fearful_shindig, fearful_twist, forbidding_bop, forbidding_canon,
forbidding_concerto, forbidding_form, forbidding_formal, forbidding_jig, forbidding_polka, forbidding_prom,
forbidding_reception, forbidding_scale, forbidding_shimmy, forbidding_shuffle, forbidding_study, forbidding_waltz,
foreboding_arrangement, foreboding_gavotte, foreboding_jitterbug, foreboding_shindig, foreboding_shuffle,
foreboding_study, formidable_jitterbug, formidable_masquerade, formidable_scale, frightening_ball, frightening_formal,
frightening_jig, frightening_masquerade, frightening_twist, funereal_concerto, funereal_honkytonk, funereal_scale,
funereal_twist, ghastly_canon, ghastly_dance, ghastly_dirge, ghastly_form, ghastly_piece, ghastly_shindig,
ghastly_twist, glum_concerto, ill_drill, ill_reception, inauspicious_boogey, inauspicious_canon, inauspicious_dance,
inauspicious_masquerade, inauspicious_prom, inauspicious_shuffle, menacing_bop, menacing_form, menacing_mixer,
menacing_scale, menacing_study, menacing_waltz, minatory_canon, minatory_concerto, minatory_formal, minatory_masquerade,
minatory_shindig, ominous_dance, ominous_prom, ominous_study, portentious_ball, portentious_dirge,
portentious_honkytonk, portentious_masquerade, portentious_waltz, sad_composition, sad_etude, sad_honkytonk,
sad_jitterbug, sad_masque, sad_reception, scary_formal, scary_masquerade, scary_piece, shocking_etude, shocking_form,
shocking_jig, shocking_masque, shocking_mixer, shocking_shindig, shocking_study, shocking_waltz, sinister_ball,
sinister_canon, sinister_etude, sinister_jig, sinister_masquerade, sinister_twist,
spine-chilling_canon, spine-chilling_dance, spine-chilling_formal, spine-chilling_gavotte, spine-chilling_honkytonk,
spine-chilling_prom, spine-chilling_shimmy, spooky_concerto, spooky_drill, spooky_etude, spooky_formal, spooky_polka,
spooky_scale, spooky_shimmy, terrible_ball, terrible_composition, terrible_concerto, terrible_polka, terrible_prom,
terrible_shindig, terrifying_drill, terrifying_mambo, terrifying_masquerade, terrifying_shindig, terrifying_shuffle,
terrifying_waltz, threatening_honkytonk, threatening_scale, threatening_shimmy, threatening_shindig,
trepidatious_composition, trepidatious_honkytonk""".replace("\n", "").replace(" ", "").split(",")


# run in binary ninja with "exec(open(r"F:\SharedSpace\current\HackASat3\blazing_etudes\automate.py").read())"

# copied from https://github.com/mborgerson/mdec/blob/master/backend/binja/mdec-binja/mdecbinja/service.py
def getDecompilation(file):
    v = open_view("./blazing_etudes/"+file)
    ds = DisassemblySettings()
    ds.set_option(DisassemblyOption.ShowAddress, False)
    ds.set_option(DisassemblyOption.WaitForIL, True)
    lv = LinearViewObject.language_representation(v, ds)
    out = []
    for f in v.functions:
        # only give decompilation for the quick_maths functions
        if not "quick_maths" in f.name: continue
        c = LinearViewCursor(lv)
        c.seek_to_address(f.highest_address)
        last = v.get_next_linear_disassembly_lines(c.duplicate())
        first = v.get_previous_linear_disassembly_lines(c)
        for line in (first + last): out.append(str(line))
    
    return '\n'.join(out)

# decompile and save
for file in files:
    dec = getDecompilation(file)
    f = open("./blazing_etudes_dec/"+file, "w")
    f.write(dec)
    f.close()