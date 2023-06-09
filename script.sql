PGDMP         ,                {            Shop    15.2    15.2 5    5           0    0    ENCODING    ENCODING        SET client_encoding = 'UTF8';
                      false            6           0    0 
   STDSTRINGS 
   STDSTRINGS     (   SET standard_conforming_strings = 'on';
                      false            7           0    0 
   SEARCHPATH 
   SEARCHPATH     8   SELECT pg_catalog.set_config('search_path', '', false);
                      false            8           1262    24583    Shop    DATABASE     z   CREATE DATABASE "Shop" WITH TEMPLATE = template0 ENCODING = 'UTF8' LOCALE_PROVIDER = libc LOCALE = 'Russian_Russia.1251';
    DROP DATABASE "Shop";
                postgres    false            �            1259    24585    category    TABLE     [   CREATE TABLE public.category (
    id integer NOT NULL,
    name character varying(255)
);
    DROP TABLE public.category;
       public         heap    postgres    false            �            1259    24584    category_id_seq    SEQUENCE     �   CREATE SEQUENCE public.category_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 &   DROP SEQUENCE public.category_id_seq;
       public          postgres    false    215            9           0    0    category_id_seq    SEQUENCE OWNED BY     C   ALTER SEQUENCE public.category_id_seq OWNED BY public.category.id;
          public          postgres    false    214            �            1259    24592    image    TABLE     ~   CREATE TABLE public.image (
    id integer NOT NULL,
    file_name character varying(255),
    product_id integer NOT NULL
);
    DROP TABLE public.image;
       public         heap    postgres    false            �            1259    24591    image_id_seq    SEQUENCE     �   CREATE SEQUENCE public.image_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 #   DROP SEQUENCE public.image_id_seq;
       public          postgres    false    217            :           0    0    image_id_seq    SEQUENCE OWNED BY     =   ALTER SEQUENCE public.image_id_seq OWNED BY public.image.id;
          public          postgres    false    216            �            1259    24648    orders    TABLE       CREATE TABLE public.orders (
    id integer NOT NULL,
    count integer NOT NULL,
    date_time timestamp(6) without time zone,
    number character varying(255),
    price real NOT NULL,
    status smallint,
    person_id integer NOT NULL,
    product_id integer NOT NULL
);
    DROP TABLE public.orders;
       public         heap    postgres    false            �            1259    24647    orders_id_seq    SEQUENCE     �   CREATE SEQUENCE public.orders_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 $   DROP SEQUENCE public.orders_id_seq;
       public          postgres    false    225            ;           0    0    orders_id_seq    SEQUENCE OWNED BY     ?   ALTER SEQUENCE public.orders_id_seq OWNED BY public.orders.id;
          public          postgres    false    224            �            1259    24599    person    TABLE     �   CREATE TABLE public.person (
    id integer NOT NULL,
    login character varying(100),
    password character varying(255),
    role character varying(255)
);
    DROP TABLE public.person;
       public         heap    postgres    false            �            1259    24598    person_id_seq    SEQUENCE     �   CREATE SEQUENCE public.person_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 $   DROP SEQUENCE public.person_id_seq;
       public          postgres    false    219            <           0    0    person_id_seq    SEQUENCE OWNED BY     ?   ALTER SEQUENCE public.person_id_seq OWNED BY public.person.id;
          public          postgres    false    218            �            1259    24608    product    TABLE     �  CREATE TABLE public.product (
    id integer NOT NULL,
    date_time timestamp(6) without time zone,
    description text NOT NULL,
    price real NOT NULL,
    seller character varying(255) NOT NULL,
    title text NOT NULL,
    warehouse character varying(255) NOT NULL,
    category_id integer NOT NULL,
    CONSTRAINT product_price_check CHECK ((price >= (1)::double precision))
);
    DROP TABLE public.product;
       public         heap    postgres    false            �            1259    24631    product_cart    TABLE     m   CREATE TABLE public.product_cart (
    id integer NOT NULL,
    person_id integer,
    product_id integer
);
     DROP TABLE public.product_cart;
       public         heap    postgres    false            �            1259    24630    product_cart_id_seq    SEQUENCE     �   CREATE SEQUENCE public.product_cart_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 *   DROP SEQUENCE public.product_cart_id_seq;
       public          postgres    false    223            =           0    0    product_cart_id_seq    SEQUENCE OWNED BY     K   ALTER SEQUENCE public.product_cart_id_seq OWNED BY public.product_cart.id;
          public          postgres    false    222            �            1259    24607    product_id_seq    SEQUENCE     �   CREATE SEQUENCE public.product_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;
 %   DROP SEQUENCE public.product_id_seq;
       public          postgres    false    221            >           0    0    product_id_seq    SEQUENCE OWNED BY     A   ALTER SEQUENCE public.product_id_seq OWNED BY public.product.id;
          public          postgres    false    220            ~           2604    24588    category id    DEFAULT     j   ALTER TABLE ONLY public.category ALTER COLUMN id SET DEFAULT nextval('public.category_id_seq'::regclass);
 :   ALTER TABLE public.category ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    214    215    215                       2604    24595    image id    DEFAULT     d   ALTER TABLE ONLY public.image ALTER COLUMN id SET DEFAULT nextval('public.image_id_seq'::regclass);
 7   ALTER TABLE public.image ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    216    217    217            �           2604    24651 	   orders id    DEFAULT     f   ALTER TABLE ONLY public.orders ALTER COLUMN id SET DEFAULT nextval('public.orders_id_seq'::regclass);
 8   ALTER TABLE public.orders ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    224    225    225            �           2604    24602 	   person id    DEFAULT     f   ALTER TABLE ONLY public.person ALTER COLUMN id SET DEFAULT nextval('public.person_id_seq'::regclass);
 8   ALTER TABLE public.person ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    219    218    219            �           2604    24611 
   product id    DEFAULT     h   ALTER TABLE ONLY public.product ALTER COLUMN id SET DEFAULT nextval('public.product_id_seq'::regclass);
 9   ALTER TABLE public.product ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    221    220    221            �           2604    24634    product_cart id    DEFAULT     r   ALTER TABLE ONLY public.product_cart ALTER COLUMN id SET DEFAULT nextval('public.product_cart_id_seq'::regclass);
 >   ALTER TABLE public.product_cart ALTER COLUMN id DROP DEFAULT;
       public          postgres    false    223    222    223            (          0    24585    category 
   TABLE DATA                 public          postgres    false    215   p9       *          0    24592    image 
   TABLE DATA                 public          postgres    false    217   �9       2          0    24648    orders 
   TABLE DATA                 public          postgres    false    225   y?       ,          0    24599    person 
   TABLE DATA                 public          postgres    false    219   �@       .          0    24608    product 
   TABLE DATA                 public          postgres    false    221   �A       0          0    24631    product_cart 
   TABLE DATA                 public          postgres    false    223   �X       ?           0    0    category_id_seq    SEQUENCE SET     =   SELECT pg_catalog.setval('public.category_id_seq', 3, true);
          public          postgres    false    214            @           0    0    image_id_seq    SEQUENCE SET     ;   SELECT pg_catalog.setval('public.image_id_seq', 50, true);
          public          postgres    false    216            A           0    0    orders_id_seq    SEQUENCE SET     <   SELECT pg_catalog.setval('public.orders_id_seq', 10, true);
          public          postgres    false    224            B           0    0    person_id_seq    SEQUENCE SET     ;   SELECT pg_catalog.setval('public.person_id_seq', 2, true);
          public          postgres    false    218            C           0    0    product_cart_id_seq    SEQUENCE SET     A   SELECT pg_catalog.setval('public.product_cart_id_seq', 7, true);
          public          postgres    false    222            D           0    0    product_id_seq    SEQUENCE SET     =   SELECT pg_catalog.setval('public.product_id_seq', 10, true);
          public          postgres    false    220            �           2606    24590    category category_pkey 
   CONSTRAINT     T   ALTER TABLE ONLY public.category
    ADD CONSTRAINT category_pkey PRIMARY KEY (id);
 @   ALTER TABLE ONLY public.category DROP CONSTRAINT category_pkey;
       public            postgres    false    215            �           2606    24597    image image_pkey 
   CONSTRAINT     N   ALTER TABLE ONLY public.image
    ADD CONSTRAINT image_pkey PRIMARY KEY (id);
 :   ALTER TABLE ONLY public.image DROP CONSTRAINT image_pkey;
       public            postgres    false    217            �           2606    24653    orders orders_pkey 
   CONSTRAINT     P   ALTER TABLE ONLY public.orders
    ADD CONSTRAINT orders_pkey PRIMARY KEY (id);
 <   ALTER TABLE ONLY public.orders DROP CONSTRAINT orders_pkey;
       public            postgres    false    225            �           2606    24606    person person_pkey 
   CONSTRAINT     P   ALTER TABLE ONLY public.person
    ADD CONSTRAINT person_pkey PRIMARY KEY (id);
 <   ALTER TABLE ONLY public.person DROP CONSTRAINT person_pkey;
       public            postgres    false    219            �           2606    24636    product_cart product_cart_pkey 
   CONSTRAINT     \   ALTER TABLE ONLY public.product_cart
    ADD CONSTRAINT product_cart_pkey PRIMARY KEY (id);
 H   ALTER TABLE ONLY public.product_cart DROP CONSTRAINT product_cart_pkey;
       public            postgres    false    223            �           2606    24616    product product_pkey 
   CONSTRAINT     R   ALTER TABLE ONLY public.product
    ADD CONSTRAINT product_pkey PRIMARY KEY (id);
 >   ALTER TABLE ONLY public.product DROP CONSTRAINT product_pkey;
       public            postgres    false    221            �           2606    24618 $   product uk_qka6vxqdy1dprtqnx9trdd47c 
   CONSTRAINT     `   ALTER TABLE ONLY public.product
    ADD CONSTRAINT uk_qka6vxqdy1dprtqnx9trdd47c UNIQUE (title);
 N   ALTER TABLE ONLY public.product DROP CONSTRAINT uk_qka6vxqdy1dprtqnx9trdd47c;
       public            postgres    false    221            �           2606    24654 "   orders fk1b0m4muwx1t377w9if3w6wwqn    FK CONSTRAINT     �   ALTER TABLE ONLY public.orders
    ADD CONSTRAINT fk1b0m4muwx1t377w9if3w6wwqn FOREIGN KEY (person_id) REFERENCES public.person(id);
 L   ALTER TABLE ONLY public.orders DROP CONSTRAINT fk1b0m4muwx1t377w9if3w6wwqn;
       public          postgres    false    219    225    3210            �           2606    24624 #   product fk1mtsbur82frn64de7balymq9s    FK CONSTRAINT     �   ALTER TABLE ONLY public.product
    ADD CONSTRAINT fk1mtsbur82frn64de7balymq9s FOREIGN KEY (category_id) REFERENCES public.category(id);
 M   ALTER TABLE ONLY public.product DROP CONSTRAINT fk1mtsbur82frn64de7balymq9s;
       public          postgres    false    215    3206    221            �           2606    24659 "   orders fk787ibr3guwp6xobrpbofnv7le    FK CONSTRAINT     �   ALTER TABLE ONLY public.orders
    ADD CONSTRAINT fk787ibr3guwp6xobrpbofnv7le FOREIGN KEY (product_id) REFERENCES public.product(id);
 L   ALTER TABLE ONLY public.orders DROP CONSTRAINT fk787ibr3guwp6xobrpbofnv7le;
       public          postgres    false    221    225    3212            �           2606    24619 !   image fkgpextbyee3uk9u6o2381m7ft1    FK CONSTRAINT     �   ALTER TABLE ONLY public.image
    ADD CONSTRAINT fkgpextbyee3uk9u6o2381m7ft1 FOREIGN KEY (product_id) REFERENCES public.product(id);
 K   ALTER TABLE ONLY public.image DROP CONSTRAINT fkgpextbyee3uk9u6o2381m7ft1;
       public          postgres    false    221    3212    217            �           2606    24642 (   product_cart fkhpnrxdy3jhujameyod08ilvvw    FK CONSTRAINT     �   ALTER TABLE ONLY public.product_cart
    ADD CONSTRAINT fkhpnrxdy3jhujameyod08ilvvw FOREIGN KEY (product_id) REFERENCES public.product(id);
 R   ALTER TABLE ONLY public.product_cart DROP CONSTRAINT fkhpnrxdy3jhujameyod08ilvvw;
       public          postgres    false    221    223    3212            �           2606    24637 (   product_cart fksgnkc1ko2i1o9yr2p63ysq3rn    FK CONSTRAINT     �   ALTER TABLE ONLY public.product_cart
    ADD CONSTRAINT fksgnkc1ko2i1o9yr2p63ysq3rn FOREIGN KEY (person_id) REFERENCES public.person(id);
 R   ALTER TABLE ONLY public.product_cart DROP CONSTRAINT fksgnkc1ko2i1o9yr2p63ysq3rn;
       public          postgres    false    223    3210    219            (      x���v
Q���W((M��L�KN,IM�/�T��L�Q�K�M�Ts�	uV�0�QP�0����x��uMk.OҌ01���ۀ�2�01�b�Ŧ�.l���b����b녽v\�1�� �6VG      *   j  x���K�\5�����H�Q�]~��P�H`��v9�#BD�}���޽�Qk�����|�߾{���no�}����s��y<=�j����|s[Ͽ�O�ٯ���������O����ǯ�����/��c�1Vԥ1����(��7f)�$O?��ś[x�ի�'����m�J!�$�I���hTE������"�}F�:�
��aN����Hq���z
�"6[*1�-*�"i�E=8S��{�B)O�QDa s�h�J^5��X��ܩ�5�>W�C�=;+��D�UH����F)���R�]ى�Ȱ��H��r���2h��G-)�U�
�92�*�� j�IL5�PҨå����#u�KV�F1��0"�9���\"נ��92��ƴL�f'Uqj�#9���ɚ]�9Gn���*����S:�����V�Q�o�3�|LxN�0���$���s�Z�����s����K��$@A�æXi$<U���s���At$ksDdq8�m:-�,��%镟cd���+�1%�VÔT��a�\l$Y=^�9Gn�x��w��`���L�9Ӕ��_�I��p��\1�9`@���(v3g��b��s����[c���@|�^'�J)1�hIW|Α[?)L.RL�v��X)�X%/K���92��\�]��:n/��th��u�����)��`U<������8eH}.fC|���	�|����GU�����S2�WťVg�}\�9Gn�pM�T��d׾Kp�&ǔѵ��%���	��c���t�a�Vڤ�:LQ8\�9Fƭ�
���P*�~��Bk��4a-�a������D84T��1��D��W�r�O#��[��[A�=�ٔbh@m&B���y$t��_:Gn���Qj�	R�Hz�9G���s�]A��.�-��J��D���\=��ݮ�#��Z]�::{�h�:���4'Æ2U�����9r+(i�� .h�B�VQfR�1s���_�����eRSI������Գ����oL��s�vք����`��=�{D�z�Uf�t��Z3�����"]�����e�"C�>�t��� �kb�5Ʈ��٦E-ʂUz@~W�Α�AZF�+U�UL&֡V��R[ܱ�]�#�\<�1� Y��Lho�0��!��3ޯM��@��q�LL#��(~h�����{�=�y���Z}a6����Z�;>V�PP�%��4MG�����
�u�֢9w��e;G������wy�dkdZ:4F���� �c����B�m��C�����c�)��``n��2�`,s��֬�Î>S�2_��0���l-[F_׉�(W|�������./[�93m-,aO��߫i���'�Tt`ߌ�҃��W���ӕ      2   K  x���MK1�{EnU�,��L6��<x(H�^��c��m�����(��zJ����w�~�{ܨ�z�Sx���0�<���.U*��X�ԍy;��r���[�C���.��4v�t*eY9���q8�)���^n��ԕ�Tj�I�H
MklK�&j<ʲt!
�>��NNېEwN�<5Q�y����RX�����2��'@��`�9C�<���#m�-�f�S�{���O�����5P7����ML�Z���N� ��w�J�y�/�\� ��BӲ���G�!	N{�%��{���.���Bg�es�V|9�_b�_FD>� �w      ,   �   x���AO�0 �;�����0Opt+T8=lE+����_/���^^�^>�n�,(�	j�����yfmmƏmgQ���˩��5s�qm��1�Q֟mgLAwKݹ�מ���ZՒ�7xX,6	>v<���,~��8���!�Q\G/m.�����	J�����s�?�7��+X®��n�޳<X���0Uՠ����$�������n<��'��b�\\��k�\�      .      x��\�nWv}�WT�<MNw���Γ0Ѓ_�y(�#[�D#��E)���'�,��	2A�Plv��W�U�����ԩ���	`C0,��Uu�ٗ�׾�������FW�������������O�޹������֭Zt����o��>�t?n޻yw����;�ԢO�n�t��ۼ}{�n-��ھ�~��w7���g�܏7ݍ�t���ݺu)����|t��b����;�Ԣ��8=M��0��G�?g��W���K�h�]kf���l�e�t���ӹ�z��t��y�����{�N�g�������u_<������&Q:N�l7M�Z�����>�-�;�Yϭ4��#��������2n	�y��lW6�-�	.�F��=����s��e�������ܯ���Y�p�� =î�z�ɓ��.V�dO��I�e�|wi�߉(
9J�IC��ݗ��E8�d���G���=2�d�G�㱻��=wΓ��e�"My\�}���b�/���k��O�ψ���KDX�)�[�۲����:v׎UfO��x*�6\$�\����:�-�l�Ʌ�ྊ�3Hǭ(�]���S9iBٜF���[�PNܗ��۩��Xfl�q���DwR� ��Ш�(�/�+��d*����R4��Ɤt����!p�h���0�B�?�!vy�X�S����c���H�h�Y;d%�;SS:u�M��t(��7���ѹS=-�(������B#X���=�׀�����˻[`�=�Oq�X��wq��lAt��ǐ�C��ZA��..���p#�}���vݩ���_�}C�_b[�r �rԨכ��F��f�r�麝�E��x]�����첾s�],����%ư��&)?��IS��[qRx��Ἳ�Q�
1>��?���1_b�u9e���Od���h	Р�]�Q�qQw<౾H=�#LԍVs���Qǩg{*���?�����a��S�VZ��zc՝�En�x\����E���{]b�_&%Gq��	w=�U��1��qt�q��0B�BI&
����w �]�)�s��w��?�}�>���)z�4�v�\��>��o��xo\rb�����=��2��V�P�L�x��y!� ���E]��1_�@Y�b����������s/��	Q 7�8��B�1�wl�����1�U��ɧ8u֭���6�P��O�a�e{��<U�$!q>�Co�aJ/w��6��3B�`R����A�g"�,�L_s�]X���:<Ch�I�`f�%�'�6F�S���gX���'��� �bY 1@�U��3����8h�zn��D�f��܃^�jQ��Zʸ����ӆ������A��2$ ��a�*��ßþ��E�ƥ�}���J�W�F����R���hE�F���i�,�כ++�~�n�ֳ�f����v��yb�c1���d&?%��Z��"3��-ԉ���f�JU�k+'�����n���@�.�� �|y�q��?��K�*lxd�l�%+^�	,>�(Ńo,9B�=��;�q�q(/�Z�p9�yD��f_�~�턄�L���;��5�,�\`bH, ��� �)%H�P�1�EQ82�>/a�J�0.�)���Q�-y�;�<C�8�Z�����u�?𲙊z��$2��.T���ˀ� BK�:���j9��h�|��p�s��ZB'آ��ތ|vXA�R��p:�oY�:b�e�,:�xbi/���W����)Ô�>��c�9wL��9�"��N5�����=�G�#��(�.��+RV��i�V)�B�S��)���T]�I�ׅ�~"�o���6%g^x��쾽O�QaizMo�$$|��[33մ� ��3r0�]�\BO�R�2Wi"�=+2���l��=�nA �Р�@h�C�5�[��~��%y�,򅃈DD����g��<�5hH9�"딯5C�S0��\��m��R4��r�ʢN�F>�z��!�v7L�8��c��������(y��@�9�+Qg�yrBda�
�mY�Ŝ�j�� yevQu
'�.�#��C��9uhl4Ql�	������ _J7]�М��%r>�N�Fhyq�+��?��\�ҏe�=a�'yH�FL���_�d�#Ȕ��)e!�f�1^�0
)�������/^p�Z��jת����R�|[��\�Xm47�uk��?�]p��ؑ���-�1�w�D~��z��j.�������l�L]^��K�ry(�b��o��3����VQ�籡� �Roл"V�z��n�`Rɑ?]���T �>H�q�Z�6�0FjFdQ#
���EKaL,���F�@b��J�3+N�aj��A%��b:���QW���y\�"W�
�+S���~NZ"��Q[5���O������$|6̬���6��F��5k��sIq��`4p"6���`#M�IV$�zs���$#�%����Q���bjA*7��2P#O�D�T���R���P���!���q�q1�[A�&/�(/yʮ*����S��P%�f5:*a:�y����bq�U�hjU���=QϛkN5�HGE�k,�u}�!�$hI @)jQQ��� \|�H��d�H�'��J�-S�R`�9]��*m����$^OB)$FՃBt�kK�i�ml�B_o*��\��|
Js���w��	�^߼������Ri�5Z`����sB���j�j�Y��ˍ����6���Z��7	\&/0+_#]���;���P�)2w�+�Hѕ�\�s�|O� )�o��5*Udf��h���:w�`oBМ�g�kB+����	�Ү��j��,��k& ����������.am�qhfa�wV�m\@�BیU�)��|�,��&��6(eHKs$(<M��x�����/�������4×������5��&k���B��WA�H�\���9�U���6�=��4F��ԇ�o�PHÙ0���?,wq�Fm�}�L�Tj)���&P�&;)x�{Db��`|��4�Wd���t(��K�I��>�B�`Yڲ�^=6�J�O��w��#ۜ~������b8��� )�sv�M
N�5�SF>TZ�.�XS���$���c�z"P��� ��_����Y����?���)T!�x%�����K����Q��h-�ox�*E�v��X[^]k���h��QwY��:��Vmy�'9{��H�;2�{��FGh�c�<EXt�B�bk�жϞ֬kEМ���W�`64�1k&�8�k���P�v,�j!B'L�#�J*����g�� /2X��ŋ ���Rlkj��Aq9	����*�@�z�������@̴�Y���	a�ZK�l��Ȃ�k!5԰&�Q�:G�fh%�Wo%�����������N����F[��p�,Y�u�@b��1��XIsa�#��R2��O�	Y�Db����Ki<'��Z4P����X���X�/�;>�|up�:�mk(i`�M��ے-ٸ}�*��r�#?�'�&=�`$G���M3�1e�*@����f�J�[�����"�Y�s+��5�`q!����Jث��j��f���Q���w�1%�v5T7;��rk���,�k���0'�@'f+�H�?MFD��M�o���)��$iI�ԗ�����UE	ɛ���l�C�b11�r�ڼϢ���v��>,n;x/h.y��1���B���J���W��Z�Y�6�_u��#�!o�XFq�$#o�kZ���C;F����a'R_:¶�Xv���88r��n��>�F���[�"�$���}�xt`n@/r<Ӣ�NȾ��">Cegjz���5���Zma'[��Y�#�ʮ�,�1�"G@�����\���m�+ׯ��l�,1�NR�Nqp�:(�0/X��E��頧���E6�u��K�r�-L�q#� �u�@	DW[=��>�i��@�ǖ�Y��0�i�(�����Z�^�h��j��p_��){��q��n+��"�#};6δp�g���W�,�I1dȪ�S|��
x��V�����O8�-5g �  ��������N��M5EV��[R3�҂���hj��|�A�U�����4t��J�Y�6��l���(F�q��#��(k�9���#e���,2�أA?�'@��br4�y٠�q+̲HZ�]��9a@�}��e�A���{̃ED�D[L�$�8@`c�[�L�#�_�j����j�	Z?E��V��\V�����W�bxI�#|j�{0���̦ǐb���]��7�}v�v�f:rAMm�|y�4���J�5O�L"����O>�\���ZT��`��� �������4�ˮ���iH��l��`�I��	r�D�7۝O�x��͏9_n���il���2�e�rw���{Q���o����sHj�g'��U����W�7V֚�5l�?`|��Ƅ�/d�P���1˽e����rҩ�7^Ş��(�H'�}C��Dq��<�D�[�����Zé�ӱ_#�ý"jj�4*;�6�p�1��KIl�W�h�X)ۦ�.|d���ϗ�a'J��e�/��ti^�^���|��[����zͺ_9�J	DIB�[�T>��쯢؊lJE5K*�Ȩ,f|���gE߱k�{�$���g����i���4x�ȴZ�&�d���M}�0N� �OS{1�X��.z`�Μ:�T��&��`I�' H�JT�<0g
� �FF��:�����I^�G�$4�u��ah}V�jӄ��5�H	)�4��X�D�oZ0
+k�'����O0M�|�Q�.4���ݳW`�ƌ��ת��b��Q��OεI�8��yb��Dc�`��^r?=�'�6���#���S�ZЮ��0�wk�H���^��Ai��|���j��/G`��:be���%���g*�:#�'��3fwZl-�����R��&^y{C:�)��R��Ӫ_���I0�S̶�c}�a���h�=�� g*l����{���s	;�a��A+������5��i��T,��:��1�yJ�h]��́'$�B��?��l�:g���|n$S��A�mݑ�������;�\~�~���0��*sZ�����Vk�|qn<�s�12��p����R�Ϭ����/
�?����k��	q���5U!����h��%�c-���+Ƽ�7�2¬XK j�2�`���80�c4��3��x�LG�e�|P$��'��`m�s@�fk����nݸ'H����z���;��z{}���������w�u�)�Wd2&ZYr.�+GB�5�C��6�h���X��X�R�)��>�qw�ݫ��b�O�5̦��YՑ�䇬��B�5�8���ωC^�
��9�GVĘ��('ǜ�9�Je����`��]{���/Y�zD��N$�pZd�����~�j��r6�a�r�Ū���܉�u}��������A��!�a��9��Y�)�? O=�?���)|��_�?\��Bh,G�s�u^jX�X��;5�Wqr���I�£T��Z�~�DFɩ_ �ʁ�� ��@0�b #�߆f�	8�[������y�w)^ǹ0JoyL���)lO��ɩ���}��i�[���\t�-^�&~4��-�[@Y�>
=�?3����K]C�N��_3bڨ�"��-��I�L1��}����9E�Rm��� e������2�e���VD�:2��X[L&q�	�3W�Rk������bP�.s����ꀤè��b���S8�t��ޕ�[����߹|���^1���[���ڞ      0   
   x���         