use obi::{OBIDecode, OBISchema, OBIEncode};
use hex::decode as HexDecode;
use base64::decode as b64decode;

use crate::libraries::multi_store;
use crate::libraries::block_header_merkle_path;
use crate::libraries::tm_signature;
use crate::libraries::result_codec;
use crate::libraries::iavl_merkle_path;

#[derive(OBIDecode, OBISchema, OBIEncode, Debug)]
pub struct RelayCandidateBlockInput {
    pub multi_store: multi_store::Data,
    pub merkle_paths: block_header_merkle_path::Data,
}

#[derive(OBIDecode, OBISchema, OBIEncode, Debug)]
pub struct AppendSignatureInput {
    pub block_height: u64,
    pub signatures: Vec<tm_signature::Data>,
}

#[derive(OBIDecode, OBISchema, OBIEncode, Debug)]
pub struct VerifyAndSaveResultInput {
    pub block_height: u64,
    pub result: result_codec::Result,
    pub version: u64,
    pub merkle_paths: Vec<iavl_merkle_path::Data>
}

#[cfg(test)]
mod test {
    use super::*;
    use hex::encode as HexEncode;

    #[test]
    fn decode_test() {
        let res: RelayCandidateBlockInput = OBIDecode::try_from_slice(HexDecode("00000040333943333144333038393738383037394532363837374138423531363430424530464343443339313833334434353834354442344433443037304144423145340000004034314631324536463635344539323746343437364546453943373130414135413346314234414446353945383839394133344442353738424442313139384430000000403939444144303438363041364234453737374136424641363045373544433131434145343839333535353644353730413743363235453544453532443446384100000040423138423136354135434139354641323734443342373942453543413935303134364438333742383736304336353536334535384231413442344434433933450000004043413041343444373035354442374546344446434531414145433335393943313832333934354143414131463931434145353332333943303744453030443632000000404232354245333845393434354446383431314445383434433439383046314234353237333842464338313542463731463439413337384433423030464631433100000000000c9bef0000000060f68e6f1184adc60000004038464538413832363531323334383446353446323337393732323944393335353044323733324539463342463146433034413942323046364230423042433145000000403637304646464333413631323338373845453234383245444532383046463841314631374530353845303839434646304343463841463042454236373039413700000040424245464646374532334132373932313832353743453043463037454444374131323733463731343934334643393745304544424543334631353444453932320000004030434241443044443137423630323133363231413835443538423538323331393937433139453433443544344132443543424538413333434435443641444338").unwrap().as_slice()).unwrap();
        println!("{:?}", res);
        let res: AppendSignatureInput = OBIDecode::try_from_slice(HexDecode("00000000000c9bef00000005000000403646324239433843343446313631413137333235353239413335434532373738383635423643363930353842354244383345423131413435304631443745393100000040324133353937464546373345363537313941343344324445413634453137323234373244313243383537423232363045373042364236424443383245363038321c00000020373730383032313145463942304330303030303030303030323234383041323000000090313232343038303131323230363443323845443438393435463634424246354637443634314338394230383839464137463942453838464135303734443930313937443831413143373835323241304230384632394344413837303631304144394146363046333231333632363136453634324436433631364637413639324437343635373337343645363537343332000000403642433338324339394430323435413634444434354237453046384541353643463538393733444541373741393143323542353536394431373834313637364600000040363544313434364641453646444539463936433044393234313936334237333538353842373941383539313433433531363332343145334634444231434641301b00000020373730383032313145463942304330303030303030303030323234383041323000000090313232343038303131323230363443323845443438393435463634424246354637443634314338394230383839464137463942453838464135303734443930313937443831413143373835323241304230384632394344413837303631304643453542353131333231333632363136453634324436433631364637413639324437343635373337343645363537343332000000403644374346384433303034363741373842383931333432464534463844463936443546393233303633454233423239344530453339454331413530363446453400000040333541333438353534443232454643314541433943304539333031414331443242373042303943303038463435363135383636434636333646443143303746461c00000020373730383032313145463942304330303030303030303030323234383041323000000090313232343038303131323230363443323845443438393435463634424246354637443634314338394230383839464137463942453838464135303734443930313937443831413143373835323241304230384632394344413837303631304131433946383130333231333632363136453634324436433631364637413639324437343635373337343645363537343332000000403241383936323845453730454632423632303745383231304439333531313834383946313935373244393937304337373546364531373241393631394635373800000040323344424638424534413233393336413441443038414230364637374243333030453838374342323141323446323338324334304239463742443144353441331b00000020373730383032313145463942304330303030303030303030323234383041323000000090313232343038303131323230363443323845443438393435463634424246354637443634314338394230383839464137463942453838464135303734443930313937443831413143373835323241304230384632394344413837303631303942384143433132333231333632363136453634324436433631364637413639324437343635373337343645363537343332000000403633323635443434353243323237353638453837333838413136413035443639333834373941353638394634363133303037354335353845333545393836453600000040313032353330453335343238374530454131413938343230353742343532354246303836413535384637363435373336453537374437324333413242424445441b00000020373730383032313145463942304330303030303030303030323234383041323000000090313232343038303131323230363443323845443438393435463634424246354637443634314338394230383839464137463942453838464135303734443930313937443831413143373835323241304230384632394344413837303631304539454645373131333231333632363136453634324436433631364637413639324437343635373337343645363537343332").unwrap().as_slice()).unwrap();
        println!("{:?}", res);
        let res: VerifyAndSaveResultInput = OBIDecode::try_from_slice(HexDecode("00000000000c9bef0000000966726f6d5f7363616e000000000000002f00000014000000086e65775f7365656400000000000f4240000000000000000a000000000000000a0000000000080d26000000000000000a0000000060f505a50000000060f505b900000000000000010000004400000040d86016e9f39aeac6918ef72954448f6791a0b9ce2c156a6a485ce1fdd53b9a4eda20d2251eb30e2b9f6aa82c45e3460c1ccf9d4acd0b4e28fb34fbd4f9a1d24600000000000c1f94000000140101000000000000000200000000000c1f9400000020bd581c9039884c76f83c5b4cb8a0498635b95b1af6f35b13b4cc0cda11ad877d0102000000000000000300000000000c1f940000002044a4cab612a8e17ba549801051248d7aa59f1756b7b62fb6a8247e9fb029c9de0103000000000000000500000000000c1f9400000020629444f42963b8ab46fb6579f5f904c4c964b7d61a5608d9e91680ad020aecc40104000000000000000900000000000c1f94000000200dafb2ae6455293750b8fbd5d10ad7ff5630cd508b064a171eb5949a855cdb5f0105000000000000001900000000000c1f9b0000002097857481b07d60ca72a80a1de9d97d4848450b4b5341b6788c6d77c5a87da8c50106000000000000003800000000000c1fa500000020e6244ecb708d37ea1c916e1ef668fefab213c85b96816626830bfbde9c71cd860107000000000000007200000000000c1fbb00000020b04db6b3ffda68cb81afb9615e6ddc4be3751b5f802d84b874432ad7e8475cfc010800000000000000df00000000000c1fde00000020302b227f6ffd0a99be5e0774b7ffbb74d4171c8b9c82434d3910cff0fec16d4f010900000000000001c700000000000c2033000000206c80fe9448cec35b4e1444347674362bf511f25a4bd9954a9d425aff4999d739000a000000000000039900000000000c22250000002053fc8ce0aeb2cf7126408f0c34f999e01bf3ea456488bf99a69f3480c6b276c6000b000000000000074300000000000c261600000020a3b4a3726c9f69d3615ccc2a358dc662c7fbe31a4e4aaffca5ef5d98b29244a7010c0000000000000e8800000000000c28d2000000207a94916148bacf4e19ae36e6055d4e1a9e6c4a4f7601ad29e83a57d8dd74d419000d0000000000001d6700000000000c38b3000000204a6ea9c54a229e4ffb6535b02b67745b07f00159c0ea23e5334545a2e4a058c0000e0000000000003acd00000000000c57eb00000020a7e219b9c4684a0f61b9306485ac90700c707912467be1815149276148a72f21010f000000000000761900000000000c6cce000000208be3c670a74e7acff15c25684456cd38ef672607f04a6ca2482631d584e2acdf0110000000000000ebec00000000000c96e7000000208ac27ed9c31dc9291bd90a4278e0e52cb3711d91336b2a1c82292b76e1fab9140011000000000001675b00000000000c9bee000000201008eccf8008f6b3f648a05e6a546d4ca1294a1dd2817502a229a411eda3f88001120000000000033dad00000000000c9bee00000020939ec419b4857e138a26f8e3003e3190f94b63e0273a4ed119d258d39afd5fcc011300000000000513a200000000000c9bee00000020ecfcca113efcdcb23c504ef173643ea0db0576d4e41ad17b5903d6cbd2f117670114000000000008beb800000000000c9bee000000208078ca2f9045bd928571ac33eefd5fd1386129a8f450c657049534ddad7e476c").unwrap().as_slice()).unwrap();
        println!("{:?}", res);
    }

    #[test]
    fn encode_test() {
        let candidate_block_input = RelayCandidateBlockInput {
            multi_store: multi_store::Data {
                auth_to_ibc_transfer_stores_merkle_hash: HexDecode("39C31D3089788079E26877A8B51640BE0FCCD391833D45845DB4D3D070ADB1E4").unwrap(),
                mint_store_merkle_hash: HexDecode("41F12E6F654E927F4476EFE9C710AA5A3F1B4ADF59E8899A34DB578BDB1198D0").unwrap(),
                oracle_iavl_state_hash: HexDecode("99DAD04860A6B4E777A6BFA60E75DC11CAE48935556D570A7C625E5DE52D4F8A").unwrap(),
                params_to_slash_stores_merkle_hash: HexDecode("B18B165A5CA95FA274D3B79BE5CA950146D837B8760C65563E58B1A4B4D4C93E").unwrap(),
                staking_to_upgrade_stores_merkle_hash: HexDecode("CA0A44D7055DB7EF4DFCE1AAEC3599C1823945ACAA1F91CAE53239C07DE00D62").unwrap(),
            },
            merkle_paths: block_header_merkle_path::Data {
                version_and_chain_id_hash: HexDecode("B25BE38E9445DF8411DE844C4980F1B452738BFC815BF71F49A378D3B00FF1C1").unwrap(),
                height: 826351,
                time_second: 1626771055,
                time_nano_second: 293907910,
                last_block_id_and_other: HexDecode("8FE8A8265123484F54F23797229D93550D2732E9F3BF1FC04A9B20F6B0B0BC1E").unwrap(),
                next_validator_hash_and_consensus_hash: HexDecode("670FFFC3A6123878EE2482EDE280FF8A1F17E058E089CFF0CCF8AF0BEB6709A7").unwrap(),
                last_results_hash: HexDecode("BBEFFF7E23A279218257CE0CF07EDD7A1273F714943FC97E0EDBEC3F154DE922").unwrap(),
                evidence_and_proposer_hash: HexDecode("0CBAD0DD17B60213621A85D58B58231997C19E43D5D4A2D5CBE8A33CD5D6ADC8").unwrap(),
            }
        };
        println!("RelayCandidateBlockInput: {:?}", HexEncode(OBIEncode::try_to_vec(&candidate_block_input).unwrap()));
        let append_signature_input = AppendSignatureInput {
            block_height: 826351,
            signatures: vec![
                tm_signature::Data {
                    r:HexDecode("6F2B9C8C44F161A17325529A35CE2778865B6C69058B5BD83EB11A450F1D7E91").unwrap(),
                    s:HexDecode("2A3597FEF73E65719A43D2DEA64E1722472D12C857B2260E70B6B6BDC82E6082").unwrap(),
                    v:28,
                    signed_data_prefix:HexDecode("77080211EF9B0C000000000022480A20").unwrap(),
                    signed_data_suffix:HexDecode("12240801122064C28ED48945F64BBF5F7D641C89B0889FA7F9BE88FA5074D90197D81A1C78522A0B08F29CDA870610AD9AF60F321362616E642D6C616F7A692D746573746E657432").unwrap()
                },
                tm_signature::Data {
                    r: HexDecode("6BC382C99D0245A64DD45B7E0F8EA56CF58973DEA77A91C25B5569D17841676F").unwrap(),
                    s: HexDecode("65D1446FAE6FDE9F96C0D9241963B735858B79A859143C5163241E3F4DB1CFA0").unwrap(),
                    v: 27,
                    signed_data_prefix: HexDecode("77080211EF9B0C000000000022480A20").unwrap(),
                    signed_data_suffix: HexDecode("12240801122064C28ED48945F64BBF5F7D641C89B0889FA7F9BE88FA5074D90197D81A1C78522A0B08F29CDA870610FCE5B511321362616E642D6C616F7A692D746573746E657432").unwrap()
                },
                tm_signature::Data {
                    r:HexDecode("6D7CF8D300467A78B891342FE4F8DF96D5F923063EB3B294E0E39EC1A5064FE4").unwrap(),
                    s:HexDecode("35A348554D22EFC1EAC9C0E9301AC1D2B70B09C008F45615866CF636FD1C07FF").unwrap(),
                    v:28,
                    signed_data_prefix:HexDecode("77080211EF9B0C000000000022480A20").unwrap(),
                    signed_data_suffix:HexDecode("12240801122064C28ED48945F64BBF5F7D641C89B0889FA7F9BE88FA5074D90197D81A1C78522A0B08F29CDA870610A1C9F810321362616E642D6C616F7A692D746573746E657432").unwrap()
                },
                tm_signature::Data {
                    r:HexDecode("2A89628EE70EF2B6207E8210D935118489F19572D9970C775F6E172A9619F578").unwrap(),
                    s:HexDecode("23DBF8BE4A23936A4AD08AB06F77BC300E887CB21A24F2382C40B9F7BD1D54A3").unwrap(),
                    v:27,
                    signed_data_prefix:HexDecode("77080211EF9B0C000000000022480A20").unwrap(),
                    signed_data_suffix:HexDecode("12240801122064C28ED48945F64BBF5F7D641C89B0889FA7F9BE88FA5074D90197D81A1C78522A0B08F29CDA8706109B8ACC12321362616E642D6C616F7A692D746573746E657432").unwrap()
                },
                tm_signature::Data {
                    r:HexDecode("63265D4452C227568E87388A16A05D6938479A5689F46130075C558E35E986E6").unwrap(),
                    s:HexDecode("102530E354287E0EA1A9842057B4525BF086A558F7645736E577D72C3A2BBDED").unwrap(),
                    v:27,
                    signed_data_prefix:HexDecode("77080211EF9B0C000000000022480A20").unwrap(),
                    signed_data_suffix:HexDecode("12240801122064C28ED48945F64BBF5F7D641C89B0889FA7F9BE88FA5074D90197D81A1C78522A0B08F29CDA870610E9EFE711321362616E642D6C616F7A692D746573746E657432").unwrap()
                }]
        };
        println!("AppendCandidateInput: {:?}", HexEncode(OBIEncode::try_to_vec(&append_signature_input).unwrap()));
        let verify_result_input = VerifyAndSaveResultInput {
            block_height: 826351,
            result: result_codec::Result {
                client_id: "from_scan".to_string(),
                oracle_script_id: 47,
                params: b64decode("AAAACG5ld19zZWVkAAAAAAAPQkA=").unwrap(),
                ask_count: 10,
                min_count: 10,
                request_id: 527654,
                ans_count: 10,
                request_time: 1626670501,
                resolve_time: 1626670521,
                resolve_status: 1,
                result: b64decode("AAAAQNhgFunzmurGkY73KVREj2eRoLnOLBVqakhc4f3VO5pO2iDSJR6zDiufaqgsReNGDBzPnUrNC04o+zT71Pmh0kY=").unwrap()
            },
            version: 794516,
            merkle_paths: vec![
                iavl_merkle_path::Data {
                    is_data_on_right:true,
                    sub_tree_height:1,
                    sub_tree_size:2,
                    sub_tree_version:794516,
                    sibling_hash:HexDecode("BD581C9039884C76F83C5B4CB8A0498635B95B1AF6F35B13B4CC0CDA11AD877D").unwrap()
                },
                iavl_merkle_path::Data {
                    is_data_on_right:true,
                    sub_tree_height:2,
                    sub_tree_size:3,
                    sub_tree_version:794516,
                    sibling_hash:HexDecode("44A4CAB612A8E17BA549801051248D7AA59F1756B7B62FB6A8247E9FB029C9DE").unwrap()
                },
                iavl_merkle_path::Data {
                    is_data_on_right:true,
                    sub_tree_height:3,
                    sub_tree_size:5,
                    sub_tree_version:794516,
                    sibling_hash:HexDecode("629444F42963B8AB46FB6579F5F904C4C964B7D61A5608D9E91680AD020AECC4").unwrap()
                },
                iavl_merkle_path::Data {
                    is_data_on_right:true,
                    sub_tree_height:4,
                    sub_tree_size:9,
                    sub_tree_version:794516,
                    sibling_hash:HexDecode("0DAFB2AE6455293750B8FBD5D10AD7FF5630CD508B064A171EB5949A855CDB5F").unwrap()
                },
                iavl_merkle_path::Data {
                    is_data_on_right:true,
                    sub_tree_height:5,
                    sub_tree_size:25,
                    sub_tree_version:794523,
                    sibling_hash:HexDecode("97857481B07D60CA72A80A1DE9D97D4848450B4B5341B6788C6D77C5A87DA8C5").unwrap()
                },
                iavl_merkle_path::Data {
                    is_data_on_right:true,
                    sub_tree_height:6,
                    sub_tree_size:56,
                    sub_tree_version:794533,
                    sibling_hash:HexDecode("E6244ECB708D37EA1C916E1EF668FEFAB213C85B96816626830BFBDE9C71CD86").unwrap()
                },
                iavl_merkle_path::Data {
                    is_data_on_right:true,
                    sub_tree_height:7,
                    sub_tree_size:114,
                    sub_tree_version:794555,
                    sibling_hash:HexDecode("B04DB6B3FFDA68CB81AFB9615E6DDC4BE3751B5F802D84B874432AD7E8475CFC").unwrap()
                },
                iavl_merkle_path::Data {
                    is_data_on_right:true,
                    sub_tree_height:8,
                    sub_tree_size:223,
                    sub_tree_version:794590,
                    sibling_hash:HexDecode("302B227F6FFD0A99BE5E0774B7FFBB74D4171C8B9C82434D3910CFF0FEC16D4F").unwrap()
                },
                iavl_merkle_path::Data {
                    is_data_on_right:true,
                    sub_tree_height:9,
                    sub_tree_size:455,
                    sub_tree_version:794675,
                    sibling_hash:HexDecode("6C80FE9448CEC35B4E1444347674362BF511F25A4BD9954A9D425AFF4999D739").unwrap()
                },
                iavl_merkle_path::Data {
                    is_data_on_right:false,
                    sub_tree_height:10,
                    sub_tree_size:921,
                    sub_tree_version:795173,
                    sibling_hash:HexDecode("53FC8CE0AEB2CF7126408F0C34F999E01BF3EA456488BF99A69F3480C6B276C6").unwrap()
                },
                iavl_merkle_path::Data {
                    is_data_on_right:false,
                    sub_tree_height:11,
                    sub_tree_size:1859,
                    sub_tree_version:796182,
                    sibling_hash:HexDecode("A3B4A3726C9F69D3615CCC2A358DC662C7FBE31A4E4AAFFCA5EF5D98B29244A7").unwrap()
                },
                iavl_merkle_path::Data {
                    is_data_on_right:true,
                    sub_tree_height:12,
                    sub_tree_size:3720,
                    sub_tree_version:796882,
                    sibling_hash:HexDecode("7A94916148BACF4E19AE36E6055D4E1A9E6C4A4F7601AD29E83A57D8DD74D419").unwrap()
                },
                iavl_merkle_path::Data {
                    is_data_on_right:false,
                    sub_tree_height:13,
                    sub_tree_size:7527,
                    sub_tree_version:800947,
                    sibling_hash:HexDecode("4A6EA9C54A229E4FFB6535B02B67745B07F00159C0EA23E5334545A2E4A058C0").unwrap()
                },
                iavl_merkle_path::Data {
                    is_data_on_right:false,
                    sub_tree_height:14,
                    sub_tree_size:15053,
                    sub_tree_version:808939,
                    sibling_hash:HexDecode("A7E219B9C4684A0F61B9306485AC90700C707912467BE1815149276148A72F21").unwrap()
                },
                iavl_merkle_path::Data {
                    is_data_on_right:true,
                    sub_tree_height:15,
                    sub_tree_size:30233,
                    sub_tree_version:814286,
                    sibling_hash:HexDecode("8BE3C670A74E7ACFF15C25684456CD38EF672607F04A6CA2482631D584E2ACDF").unwrap()
                },
                iavl_merkle_path::Data {
                    is_data_on_right:true,
                    sub_tree_height:16,
                    sub_tree_size:60396,
                    sub_tree_version:825063,
                    sibling_hash:HexDecode("8AC27ED9C31DC9291BD90A4278E0E52CB3711D91336B2A1C82292B76E1FAB914").unwrap()
                },
                iavl_merkle_path::Data {
                    is_data_on_right:false,
                    sub_tree_height:17,
                    sub_tree_size:91995,
                    sub_tree_version:826350,
                    sibling_hash:HexDecode("1008ECCF8008F6B3F648A05E6A546D4CA1294A1DD2817502A229A411EDA3F880").unwrap()
                },
                iavl_merkle_path::Data {
                    is_data_on_right:true,
                    sub_tree_height:18,
                    sub_tree_size:212397,
                    sub_tree_version:826350,
                    sibling_hash:HexDecode("939EC419B4857E138A26F8E3003E3190F94B63E0273A4ED119D258D39AFD5FCC").unwrap()
                },
                iavl_merkle_path::Data {
                    is_data_on_right:true,
                    sub_tree_height:19,
                    sub_tree_size:332706,
                    sub_tree_version:826350,
                    sibling_hash:HexDecode("ECFCCA113EFCDCB23C504EF173643EA0DB0576D4E41AD17B5903D6CBD2F11767").unwrap()
                },
                iavl_merkle_path::Data {
                    is_data_on_right:true,
                    sub_tree_height:20,
                    sub_tree_size:573112,
                    sub_tree_version:826350,
                    sibling_hash:HexDecode("8078CA2F9045BD928571AC33EEFD5FD1386129A8F450C657049534DDAD7E476C").unwrap()
                }
            ]
        };
        println!("VerifyResultInput: {:?}", HexEncode(OBIEncode::try_to_vec(&verify_result_input).unwrap()));
    }
}
