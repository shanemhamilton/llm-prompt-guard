/* eslint-disable no-misleading-character-class -- CONFUSABLE_CHARS
   intentionally packs spacing combining marks (e.g. Oriya/Telugu/Malayalam
   dependent vowel signs) into a character class as disjoint code points;
   no combination happens, this is table data, not prose. */
/**
 * Generated from Unicode's confusables.txt — DO NOT EDIT BY HAND.
 * Regenerate with: npm run build:confusables
 *
 * Source: https://www.unicode.org/Public/security/latest/confusables.txt
 * Date: 2025-07-22, 05:49:37 GMT
 * Generated: 2026-09-11
 *
 * ---- Unicode License V3 (https://www.unicode.org/license.txt) ----
 * UNICODE LICENSE V3
 *
 * COPYRIGHT AND PERMISSION NOTICE
 *
 * Copyright © 1991-2026 Unicode, Inc.
 *
 * NOTICE TO USER: Carefully read the following legal agreement. BY
 * DOWNLOADING, INSTALLING, COPYING OR OTHERWISE USING DATA FILES, AND/OR
 * SOFTWARE, YOU UNEQUIVOCALLY ACCEPT, AND AGREE TO BE BOUND BY, ALL OF THE
 * TERMS AND CONDITIONS OF THIS AGREEMENT. IF YOU DO NOT AGREE, DO NOT
 * DOWNLOAD, INSTALL, COPY, DISTRIBUTE OR USE THE DATA FILES OR SOFTWARE.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of data files and any associated documentation (the "Data Files") or
 * software and any associated documentation (the "Software") to deal in the
 * Data Files or Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, and/or sell
 * copies of the Data Files or Software, and to permit persons to whom the
 * Data Files or Software are furnished to do so, provided that either (a)
 * this copyright and permission notice appear with all copies of the Data
 * Files or Software, or (b) this copyright and permission notice appear in
 * associated Documentation.
 *
 * THE DATA FILES AND SOFTWARE ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
 * KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF
 * THIRD PARTY RIGHTS.
 *
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR HOLDERS INCLUDED IN THIS NOTICE
 * BE LIABLE FOR ANY CLAIM, OR ANY SPECIAL INDIRECT OR CONSEQUENTIAL DAMAGES,
 * OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THE DATA
 * FILES OR SOFTWARE.
 *
 * Except as contained in this notice, the name of a copyright holder shall
 * not be used in advertising or otherwise to promote the sale, use or other
 * dealings in these Data Files or Software without prior written
 * authorization of the copyright holder.
 *
 * ---------------------------------------------------------------
 */

// Alternating [confusable char][ASCII target char] pairs, sorted by code
// point. Iterate with `for...of` (code-point-aware) to rebuild the map.
const CONFUSABLE_PAIRS =
  "¢c¥YÐD×xØOøoþpĐDđdĦHħhıiŁLłlŋnŦTŧtſfƀbƂbƃbƄbƉDƌdƍgƑFƒfƖlƗlƙkƚlƝNƞnƟOƥpƦRƧ2ƭtƮTƴyƵZƶzƷ3ƻ2Ƽ5ƽsƿpǀlǤGǥgǾOȜ3Ȣ8ȣ8ȤZȥzȼcȾTɄUɆEɇeɈJɉjɍrɎYɏyɑaɓbɖdɗdɠgɡgɣyɦhɨiɩiɪiɫlɭlɯwɳnɵoɼrɽrʂsʋuʏyʐzʠq˛iͺiͿJΑAΒBΕEΖZΗHΘOΙlΚKΜMΝNΟOΡPΤTΥYΧXαaγyηnθOιiνvοoρpσoυuϑOϒYϜFϨ2Ϭ6ϭoϱpϲcϳjϴOϸpϹCϺMЅSІlЈJАAБbВBЕEЗ3КKМMНHОOРPСCТTУYХXЬbаaб6гrеeоoрpсcуyхxшwѕsіiјjћhџuѡwѢbѣbѲOѳoѴVѵvѽwҌbҍbғrҘ3ҚKҞKҢHҪCҫcҬTҮYүyҰYұyҲXһhҽeҿeӀlӇHӉHӍMӏlӠ3ӨOөoԁdԌGԛqԜWԝwՍUՏSՕOաwգqզqհhղnոnռnսuցgւiքfօo׀lוlטvןlסoإlاlهo١l٥o٧Vٳlھoہoەo۱l۵o۷Vۿo߀Oߊl०o३3০o৪8৭9੦o੧9੪8૦o૩3ଃ8ଠO୦o୨9௦oంo౦oಂo೦Oംoടsഠo൦o൭9ංo๐o໐oငcတoဝo၀oၚcთoყyჿoሀUዐOᎠDᎡRᎢTᎥiᎩYᎪAᎫJᎬEᎳWᎷMᎻHᎽYᎾOᏀGᏂhᏃZᏌUᏎ4ᏏbᏒRᏔWᏕSᏙVᏚSᏞLᏟCᏢPᏦKᏧdᏫOᏮ6ᏲhᏳGᏴBᐯVᑌUᑭPᑯdᑲbᑳbᒍJᒪLᒿ2ᕁxᕼHᕽxᖇRᖯbᖴFᗅAᗞDᗪDᗰMᗷB᙭X᙮xᚷXᛁlᛕKᛖM០oᴄcᴏoᴑoᴜuᴠvᴡwᴢzᴦrᵮfᵰnᵲrᵴsᵵtᵶzᵸHᵻiᵼiᵽpᵾuᶃgᶌyᶢgẚaẝfỿyιi⁰o₡C₩W₫d₭K₮Tℏhℐlℑl℮eℽyⅠl∣l∨v∪U⊖O⊝O⊤T⋁v⋃U⋿E⍡T⍬O⍳i⍴p⍶a⍸i⍺a⏽lⓛI╳X⟙T⤫x⤬x⨯x⨰xⱧHⱩKⲂBⲅrⲎHⲐOⲑoⲒlⲓiⲔKⲘMⲚNⲜ3ⲞOⲟoⲢPⲣpⲤCⲥcⲦTⲨYⲩyⲬXⲽwⳄ3Ⳋ9ⳋ9Ⳍ3ⳎPⳏpⳐLⳒ6ⳓ6Ⳝ6ⴱOⴸVⴹEⵁOⵏlⵔOⵕQⵝX〇OꓐBꓑPꓒdꓓDꓔTꓖGꓗKꓙJꓚCꓜZꓝFꓟMꓠNꓡLꓢSꓣRꓦVꓧHꓪWꓫXꓬYꓮAꓰEꓲlꓳOꓴUꙄ2ꙇiꚕhꛟVꛯ2ꜱsꝀKꝊOꝋoꝚ2ꝡwꝪ3Ꝯ9ꞘFꞙfꞟuꞫ3ꞲJꞳXꞴBꬲeꬵfꬽoꬾoꭇrꭈrꭎuꭒuꭚyꭴoꭵiꮁrꮃwꮎoꮓzꮜuꮩvꮪsꮯcꮻoﮦoﮧoﮨoﮩoﮪoﮫoﮬoﮭoﳙoﴼlﴽlﺇlﺈlﺍlﺎlﻩoﻪoﻫoﻬoＩl￨l𐆎N𐆖X𐆗V𐊂B𐊆E𐊇F𐊊l𐊐X𐊒O𐊕P𐊖S𐊗T𐊠A𐊡B𐊢C𐊥F𐊫O𐊰M𐊱T𐊲Y𐊴X𐋏H𐋵Z𐌁B𐌂C𐌉l𐌑M𐌕T𐌗X𐌚8𐌠l𐌢X𐐄O𐐕C𐐛L𐐠S𐐬o𐐽c𐑈s𐒴R𐓂O𐓎U𐓒7𐓪o𐓶u𐔓N𐔖O𐔘K𐔜C𐔝V𐔥F𐔦L𐔧X𑓅w𑓐o𑜆v𑜊w𑜎w𑜏w𑢠V𑢢F𑢣L𑢤Y𑢦E𑢩Z𑢬9𑢮E𑢯4𑢲L𑢵O𑢸U𑢻5𑢼T𑣀v𑣁s𑣂F𑣃i𑣄z𑣆7𑣈o𑣊3𑣌9𑣕6𑣖9𑣗o𑣘u𑣜y𑣠O𑣥Z𑣦W𑣩C𑣬X𑣯W𑣲C𑷚l𑷠O𑷡l𖺪l𖺶b𖼈V𖼊T𖼖L𖼨l𖼵R𖼺S𖼻3𖽀A𖽂U𖽃Y𜳞l𜳰O𜳱l𝈆3𝈍V𝈒7𝈓F𝈖R𝈚O𝈪L𝐈l𝐼l𝑰l𝓘l𝕀l𝕴l𝖨l𝗜l𝘐l𝙄l𝙸l𝚤i𝚨A𝚩B𝚬E𝚭Z𝚮H𝚯O𝚰l𝚱K𝚳M𝚴N𝚶O𝚸P𝚹O𝚻T𝚼Y𝚾X𝛂a𝛄y𝛈n𝛉O𝛊i𝛎v𝛐o𝛒p𝛔o𝛖u𝛝O𝛠p𝛢A𝛣B𝛦E𝛧Z𝛨H𝛩O𝛪l𝛫K𝛭M𝛮N𝛰O𝛲P𝛳O𝛵T𝛶Y𝛸X𝛼a𝛾y𝜂n𝜃O𝜄i𝜈v𝜊o𝜌p𝜎o𝜐u𝜗O𝜚p𝜜A𝜝B𝜠E𝜡Z𝜢H𝜣O𝜤l𝜥K𝜧M𝜨N𝜪O𝜬P𝜭O𝜯T𝜰Y𝜲X𝜶a𝜸y𝜼n𝜽O𝜾i𝝂v𝝄o𝝆p𝝈o𝝊u𝝑O𝝔p𝝖A𝝗B𝝚E𝝛Z𝝜H𝝝O𝝞l𝝟K𝝡M𝝢N𝝤O𝝦P𝝧O𝝩T𝝪Y𝝬X𝝰a𝝲y𝝶n𝝷O𝝸i𝝼v𝝾o𝞀p𝞂o𝞄u𝞋O𝞎p𝞐A𝞑B𝞔E𝞕Z𝞖H𝞗O𝞘l𝞙K𝞛M𝞜N𝞞O𝞠P𝞡O𝞣T𝞤Y𝞦X𝞪a𝞬y𝞰n𝞱O𝞲i𝞶v𝞸o𝞺p𝞼o𝞾u𝟅O𝟈p𝟊F𝟎O𝟏l𝟘O𝟙l𝟢O𝟣l𝟬O𝟭l𝟶O𝟷l𞣇l𞣋8𞸀l𞸤o𞹤o𞺀l𞺄o🅮C🜈V🜔O🝌C🝨T🯰O🯱l";

function buildConfusablesMap(pairs: string): ReadonlyMap<string, string> {
  const map = new Map<string, string>();
  const chars = [...pairs];
  for (let i = 0; i < chars.length; i += 2) {
    map.set(chars[i], chars[i + 1]);
  }
  return map;
}

/** Confusable (non-ASCII) character → its single-ASCII-char fold. */
export const CONFUSABLES_TO_ASCII: ReadonlyMap<string, string> =
  buildConfusablesMap(CONFUSABLE_PAIRS);

/** Character class matching every confusable source code point above. */
export const CONFUSABLE_CHARS = /[\u00a2\u00a5\u00d0\u00d7-\u00d8\u00f8\u00fe\u0110-\u0111\u0126-\u0127\u0131\u0141-\u0142\u014b\u0166-\u0167\u017f-\u0180\u0182-\u0184\u0189\u018c-\u018d\u0191-\u0192\u0196-\u0197\u0199-\u019a\u019d-\u019f\u01a5-\u01a7\u01ad-\u01ae\u01b4-\u01b7\u01bb-\u01bd\u01bf-\u01c0\u01e4-\u01e5\u01fe\u021c\u0222-\u0225\u023c\u023e\u0244\u0246-\u0249\u024d-\u024f\u0251\u0253\u0256-\u0257\u0260-\u0261\u0263\u0266\u0268-\u026b\u026d\u026f\u0273\u0275\u027c-\u027d\u0282\u028b\u028f-\u0290\u02a0\u02db\u037a\u037f\u0391-\u0392\u0395-\u039a\u039c-\u039d\u039f\u03a1\u03a4-\u03a5\u03a7\u03b1\u03b3\u03b7-\u03b9\u03bd\u03bf\u03c1\u03c3\u03c5\u03d1-\u03d2\u03dc\u03e8\u03ec-\u03ed\u03f1-\u03f4\u03f8-\u03fa\u0405-\u0406\u0408\u0410-\u0412\u0415\u0417\u041a\u041c-\u041e\u0420-\u0423\u0425\u042c\u0430-\u0431\u0433\u0435\u043e\u0440-\u0441\u0443\u0445\u0448\u0455-\u0456\u0458\u045b\u045f\u0461-\u0463\u0472-\u0475\u047d\u048c-\u048d\u0493\u0498\u049a\u049e\u04a2\u04aa-\u04ac\u04ae-\u04b2\u04bb\u04bd\u04bf-\u04c0\u04c7\u04c9\u04cd\u04cf\u04e0\u04e8-\u04e9\u0501\u050c\u051b-\u051d\u054d\u054f\u0555\u0561\u0563\u0566\u0570\u0572\u0578\u057c-\u057d\u0581-\u0582\u0584-\u0585\u05c0\u05d5\u05d8\u05df\u05e1\u0625\u0627\u0647\u0661\u0665\u0667\u0673\u06be\u06c1\u06d5\u06f1\u06f5\u06f7\u06ff\u07c0\u07ca\u0966\u0969\u09e6\u09ea\u09ed\u0a66-\u0a67\u0a6a\u0ae6\u0ae9\u0b03\u0b20\u0b66\u0b68\u0be6\u0c02\u0c66\u0c82\u0ce6\u0d02\u0d1f-\u0d20\u0d66\u0d6d\u0d82\u0e50\u0ed0\u1004\u1010\u101d\u1040\u105a\u10d7\u10e7\u10ff\u1200\u12d0\u13a0-\u13a2\u13a5\u13a9-\u13ac\u13b3\u13b7\u13bb\u13bd-\u13be\u13c0\u13c2-\u13c3\u13cc\u13ce-\u13cf\u13d2\u13d4-\u13d5\u13d9-\u13da\u13de-\u13df\u13e2\u13e6-\u13e7\u13eb\u13ee\u13f2-\u13f4\u142f\u144c\u146d\u146f\u1472-\u1473\u148d\u14aa\u14bf\u1541\u157c-\u157d\u1587\u15af\u15b4\u15c5\u15de\u15ea\u15f0\u15f7\u166d-\u166e\u16b7\u16c1\u16d5-\u16d6\u17e0\u1d04\u1d0f\u1d11\u1d1c\u1d20-\u1d22\u1d26\u1d6e\u1d70\u1d72\u1d74-\u1d76\u1d78\u1d7b-\u1d7e\u1d83\u1d8c\u1da2\u1e9a\u1e9d\u1eff\u1fbe\u2070\u20a1\u20a9\u20ab\u20ad-\u20ae\u210f-\u2111\u212e\u213d\u2160\u2223\u2228\u222a\u2296\u229d\u22a4\u22c1\u22c3\u22ff\u2361\u236c\u2373-\u2374\u2376\u2378\u237a\u23fd\u24db\u2573\u27d9\u292b-\u292c\u2a2f-\u2a30\u2c67\u2c69\u2c82\u2c85\u2c8e\u2c90-\u2c94\u2c98\u2c9a\u2c9c\u2c9e-\u2c9f\u2ca2-\u2ca6\u2ca8-\u2ca9\u2cac\u2cbd\u2cc4\u2cca-\u2ccc\u2cce-\u2cd0\u2cd2-\u2cd3\u2cdc\u2d31\u2d38-\u2d39\u2d41\u2d4f\u2d54-\u2d55\u2d5d\u3007\ua4d0-\ua4d4\ua4d6-\ua4d7\ua4d9-\ua4da\ua4dc-\ua4dd\ua4df-\ua4e3\ua4e6-\ua4e7\ua4ea-\ua4ec\ua4ee\ua4f0\ua4f2-\ua4f4\ua644\ua647\ua695\ua6df\ua6ef\ua731\ua740\ua74a-\ua74b\ua75a\ua761\ua76a\ua76e\ua798-\ua799\ua79f\ua7ab\ua7b2-\ua7b4\uab32\uab35\uab3d-\uab3e\uab47-\uab48\uab4e\uab52\uab5a\uab74-\uab75\uab81\uab83\uab8e\uab93\uab9c\uaba9-\uabaa\uabaf\uabbb\ufba6-\ufbad\ufcd9\ufd3c-\ufd3d\ufe87-\ufe88\ufe8d-\ufe8e\ufee9-\ufeec\uff29\uffe8\u{1018e}\u{10196}-\u{10197}\u{10282}\u{10286}-\u{10287}\u{1028a}\u{10290}\u{10292}\u{10295}-\u{10297}\u{102a0}-\u{102a2}\u{102a5}\u{102ab}\u{102b0}-\u{102b2}\u{102b4}\u{102cf}\u{102f5}\u{10301}-\u{10302}\u{10309}\u{10311}\u{10315}\u{10317}\u{1031a}\u{10320}\u{10322}\u{10404}\u{10415}\u{1041b}\u{10420}\u{1042c}\u{1043d}\u{10448}\u{104b4}\u{104c2}\u{104ce}\u{104d2}\u{104ea}\u{104f6}\u{10513}\u{10516}\u{10518}\u{1051c}-\u{1051d}\u{10525}-\u{10527}\u{114c5}\u{114d0}\u{11706}\u{1170a}\u{1170e}-\u{1170f}\u{118a0}\u{118a2}-\u{118a4}\u{118a6}\u{118a9}\u{118ac}\u{118ae}-\u{118af}\u{118b2}\u{118b5}\u{118b8}\u{118bb}-\u{118bc}\u{118c0}-\u{118c4}\u{118c6}\u{118c8}\u{118ca}\u{118cc}\u{118d5}-\u{118d8}\u{118dc}\u{118e0}\u{118e5}-\u{118e6}\u{118e9}\u{118ec}\u{118ef}\u{118f2}\u{11dda}\u{11de0}-\u{11de1}\u{16eaa}\u{16eb6}\u{16f08}\u{16f0a}\u{16f16}\u{16f28}\u{16f35}\u{16f3a}-\u{16f3b}\u{16f40}\u{16f42}-\u{16f43}\u{1ccde}\u{1ccf0}-\u{1ccf1}\u{1d206}\u{1d20d}\u{1d212}-\u{1d213}\u{1d216}\u{1d21a}\u{1d22a}\u{1d408}\u{1d43c}\u{1d470}\u{1d4d8}\u{1d540}\u{1d574}\u{1d5a8}\u{1d5dc}\u{1d610}\u{1d644}\u{1d678}\u{1d6a4}\u{1d6a8}-\u{1d6a9}\u{1d6ac}-\u{1d6b1}\u{1d6b3}-\u{1d6b4}\u{1d6b6}\u{1d6b8}-\u{1d6b9}\u{1d6bb}-\u{1d6bc}\u{1d6be}\u{1d6c2}\u{1d6c4}\u{1d6c8}-\u{1d6ca}\u{1d6ce}\u{1d6d0}\u{1d6d2}\u{1d6d4}\u{1d6d6}\u{1d6dd}\u{1d6e0}\u{1d6e2}-\u{1d6e3}\u{1d6e6}-\u{1d6eb}\u{1d6ed}-\u{1d6ee}\u{1d6f0}\u{1d6f2}-\u{1d6f3}\u{1d6f5}-\u{1d6f6}\u{1d6f8}\u{1d6fc}\u{1d6fe}\u{1d702}-\u{1d704}\u{1d708}\u{1d70a}\u{1d70c}\u{1d70e}\u{1d710}\u{1d717}\u{1d71a}\u{1d71c}-\u{1d71d}\u{1d720}-\u{1d725}\u{1d727}-\u{1d728}\u{1d72a}\u{1d72c}-\u{1d72d}\u{1d72f}-\u{1d730}\u{1d732}\u{1d736}\u{1d738}\u{1d73c}-\u{1d73e}\u{1d742}\u{1d744}\u{1d746}\u{1d748}\u{1d74a}\u{1d751}\u{1d754}\u{1d756}-\u{1d757}\u{1d75a}-\u{1d75f}\u{1d761}-\u{1d762}\u{1d764}\u{1d766}-\u{1d767}\u{1d769}-\u{1d76a}\u{1d76c}\u{1d770}\u{1d772}\u{1d776}-\u{1d778}\u{1d77c}\u{1d77e}\u{1d780}\u{1d782}\u{1d784}\u{1d78b}\u{1d78e}\u{1d790}-\u{1d791}\u{1d794}-\u{1d799}\u{1d79b}-\u{1d79c}\u{1d79e}\u{1d7a0}-\u{1d7a1}\u{1d7a3}-\u{1d7a4}\u{1d7a6}\u{1d7aa}\u{1d7ac}\u{1d7b0}-\u{1d7b2}\u{1d7b6}\u{1d7b8}\u{1d7ba}\u{1d7bc}\u{1d7be}\u{1d7c5}\u{1d7c8}\u{1d7ca}\u{1d7ce}-\u{1d7cf}\u{1d7d8}-\u{1d7d9}\u{1d7e2}-\u{1d7e3}\u{1d7ec}-\u{1d7ed}\u{1d7f6}-\u{1d7f7}\u{1e8c7}\u{1e8cb}\u{1ee00}\u{1ee24}\u{1ee64}\u{1ee80}\u{1ee84}\u{1f16e}\u{1f708}\u{1f714}\u{1f74c}\u{1f768}\u{1fbf0}-\u{1fbf1}]/gu;
