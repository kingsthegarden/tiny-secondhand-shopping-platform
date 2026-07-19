"""Chat room authorization helpers + real image upload path."""
import io
import os

from market.models import Product, db
from market.utils import dm_room_name, parse_dm_room, user_in_room
from tests.conftest import get_csrf, login

# 1x1 transparent PNG
PNG_BYTES = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000d4944415478da63fcffff3f030005fe02fea72d1e2d0000000049454e44ae426082")


def test_dm_room_name_is_order_independent():
    assert dm_room_name(7, 3) == dm_room_name(3, 7) == "dm:3:7"


def test_parse_dm_room_rejects_malformed():
    assert parse_dm_room("dm:1:2") == (1, 2)
    assert parse_dm_room("dm:2:1") is None          # wrong order
    assert parse_dm_room("dm:a:b") is None
    assert parse_dm_room("global") is None
    assert parse_dm_room("dm:1:2:3") is None


def test_user_in_room_authorization():
    assert user_in_room("global", 1)
    assert user_in_room("dm:1:2", 1) and user_in_room("dm:1:2", 2)
    # a third user must NOT be able to join someone else's DM room
    assert not user_in_room("dm:1:2", 3)
    assert not user_in_room("dm:junk", 1)


def test_real_png_upload_saved_with_random_name(app, client):
    login(client)
    token = get_csrf(client, "/products/new")
    resp = client.post("/products/new", data={
        "csrf_token": token, "title": "사진 있는 상품", "description": "d",
        "price": "5000",
        "image": (io.BytesIO(PNG_BYTES), "원본파일명 ../../evil.png"),
    }, content_type="multipart/form-data", follow_redirects=True)
    assert "상품이 등록되었습니다".encode() in resp.data

    product = db.session.execute(
        db.select(Product).filter_by(title="사진 있는 상품")).scalar_one()
    # stored name is server-generated (hex + ext), not the client filename
    assert product.image_filename.endswith(".png")
    assert "evil" not in product.image_filename
    assert "/" not in product.image_filename and ".." not in product.image_filename
    assert os.path.isfile(os.path.join(
        app.config["UPLOAD_FOLDER"], product.image_filename))
