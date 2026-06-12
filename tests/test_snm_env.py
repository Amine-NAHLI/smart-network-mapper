import os

from snm_env import load_dotenv


def test_load_dotenv_reads_file(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "TEST_SNM_VAR=hello\n# comment\nOTHER=world\n",
        encoding="utf-8",
    )
    os.environ.pop("TEST_SNM_VAR", None)
    load_dotenv(str(tmp_path))
    assert os.environ.get("TEST_SNM_VAR") == "hello"
