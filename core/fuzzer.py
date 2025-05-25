import copy
from random import randint
from time import sleep
from urllib.parse import unquote
import requests

from core.colors import end, red, green, yellow
from core.config import fuzzes, xsschecker
from core.requester import requester
from core.utils import replaceValue, counter
from core.log import setup_logger

logger = setup_logger(__name__)


def fuzzer(url, params, headers, GET, delay, timeout, WAF, encoding):
    for fuzz in fuzzes:
        if delay == 0:
            delay = 0
        t = delay + randint(delay, delay * 2) + counter(fuzz)
        sleep(t)
        try:
            if encoding:
                fuzz = encoding(unquote(fuzz))
            data = replaceValue(params, xsschecker, fuzz, copy.deepcopy)
            response = requester(url, data, headers, GET, delay / 2, timeout)
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout,
                requests.exceptions.RequestException) as e:
            logger.error(f"Network error during fuzzing: {str(e)}")
            logger.error("WAF is dropping suspicious requests.")
            if delay == 0:
                logger.info(f"Delay has been increased to {green}6{end} seconds.")
                delay += 6
            limit = (delay + 1) * 50
            timer = -1
            while timer < limit:
                logger.info(
                    f"\rFuzzing will continue after {green}{limit}{end} seconds.\t\t\r"
                )
                limit -= 1
                sleep(1)
            try:
                requester(url, params, headers, GET, 0, 10)
                logger.good(
                    f"Pheww! Looks like sleeping for {green}{((delay + 1) * 2)}{end} seconds worked!"
                )
            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout,
                    requests.exceptions.RequestException):
                logger.error("\nLooks like WAF has blocked our IP Address. Sorry!")
                break
        except Exception as e:
            logger.error(f"Unexpected error during fuzzing: {str(e)}")
            continue
        if encoding:
            fuzz = encoding(fuzz)
        if (
            fuzz.lower() in response.text.lower()
        ):  # if fuzz string is reflected in the response
            result = f"{green}[passed]  {end}"
        # if the server returned an error (Maybe WAF blocked it)
        elif str(response.status_code)[:1] != "2":
            result = f"{red}[blocked] {end}"
        else:  # if the fuzz string was not reflected in the response completely
            result = f"{yellow}[filtered]{end}"
        logger.info(f"{result} {fuzz}")
