package com.example.biddingsystem.services.impl;

import com.example.biddingsystem.dto.BidDto;
import com.example.biddingsystem.dto.BidListDto;
import com.example.biddingsystem.dto.UserBidsDto;
import com.example.biddingsystem.dto.WinningBidsDto;
import com.example.biddingsystem.exceptions.ResourceNotFoundException;
import com.example.biddingsystem.exceptions.ValidationException;
import com.example.biddingsystem.models.Bid;
import com.example.biddingsystem.models.Product;
import com.example.biddingsystem.models.UserEntity;
import com.example.biddingsystem.repositories.BiddingRepository;
import com.example.biddingsystem.repositories.ProductRepository;
import com.example.biddingsystem.services.BiddingService;
import com.example.biddingsystem.services.EmailService;
import com.example.biddingsystem.services.NotificationService;
import com.example.biddingsystem.utils.SecurityUtils;
import jakarta.transaction.Transactional;
import lombok.AllArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@AllArgsConstructor
@Transactional
public class BiddingServiceImpl implements BiddingService {

    private final BiddingRepository biddingRepository;
    private final ProductRepository productRepository;
    private final EmailService emailService;
    private final SecurityUtils securityUtils;
    private final ModelMapper modelMapper;
    private final NotificationService notificationService;
    
    @Override
    public List<UserBidsDto> getUserBids(Boolean winningBids) {
        List<Bid> userBids;

        if (winningBids) {
            userBids = biddingRepository.findByBidderUsernameAndIsWinningBidTrue(securityUtils.getCurrentUser().getUsername());
        } else {
            userBids = biddingRepository.findByBidderUsernameAndIsWinningBidFalse(securityUtils.getCurrentUser().getUsername());
        }

        if (userBids.isEmpty()) {
            return Collections.emptyList();
        }

        return userBids.stream().map(bid -> modelMapper.map(bid, UserBidsDto.class)).collect(Collectors.toList());
    }

    @Override
    public List<BidListDto> getAllBids() {
        List<Bid> bidList = biddingRepository.findAll();
        return bidList.stream().map(bid -> modelMapper.map(bid, BidListDto.class)).toList();
    }

    @Override
    public List<UserBidsDto> getLatestBids() {
        Pageable pageable = PageRequest.of(0, 10);
        Page<Bid> bidsPage = biddingRepository.findBids(pageable);
        List<Bid> bids = bidsPage.getContent();
        return bids.stream().map(bid -> modelMapper.map(bid, UserBidsDto.class)).toList();
    }

    @Override
    public void placeBid(Long productId, BidDto bidDto) {
        Optional<Product> productOptional = productRepository.findById(productId);
        if (productOptional.isEmpty()) {
            throw new ResourceNotFoundException("Product not found");
        }

        Product product = getProduct(bidDto, productOptional);
        productRepository.save(product);

        Bid bid = new Bid();
        bid.setBidder(securityUtils.getCurrentUser());
        bid.setProduct(product);
        bid.setBidAmount(bidDto.getBidAmount());
        biddingRepository.save(bid);

        // notify previous highest bidder that they have been outbid except if the previous bidder is same as new
        // highest bidder
        List<Bid> previousBids = biddingRepository.findBidsByProductIdOrderByBidAmountDesc(productId);
        if (previousBids.size() > 1) {
            Bid previousBid = previousBids.get(1);
            UserEntity previousBidder = previousBid.getBidder();
            if (!Objects.equals(previousBids.get(0).getBidder().getId(), previousBidder.getId())) {
                notificationService.sendNotification("😲 You have been outbid on " + product.getName() + " by " + previousBidder.getUsername(),
                        previousBidder.getId());
            }
        }

        // notify the seller that a new bid has been placed on their product
        notificationService.sendNotification("🎉 A new bid has been placed on " + product.getName() + " by " + previousBids.get(0).getBidder().getUsername(),
                product.getSeller().getId());
    }

    private static Product getProduct(BidDto bidDto, Optional<Product> productOptional) {
        Product product = productOptional.get();
        if (product.isBiddingClosed()) {
            throw new ValidationException("Bidding is closed for this product");
        }

        // the first user to bid on a product can bid the minimum amount otherwise it is not allowed

        if (bidDto.getBidAmount().equals(product.getMinimumBid()) &&
                !product.getMinimumBid().equals(product.getCurrentBid())) {
            throw new ValidationException("Bid amount must be greater than " + product.getCurrentBid());
        }

        if (bidDto.getBidAmount() <= product.getCurrentBid()) {
            throw new ValidationException("Bid amount must be greater than " + product.getCurrentBid());
        }

        product.setCurrentBid(bidDto.getBidAmount());
        return product;
    }

    @Override
    public List<BidListDto> getBiddingList(Long productId) {
        List<Bid> biddingList = biddingRepository.findBidsByProductIdOrderByBidAmountDesc(productId);
        if (biddingList.isEmpty()) {
            return Collections.emptyList();
        }
        return biddingList.stream().map(bid -> modelMapper.map(bid, BidListDto.class)).collect(Collectors.toList());
    }

    @Override
    public BidListDto getWinningBid(Long productId) {
        Optional<Product> productOptional = productRepository.findById(productId);
        if (productOptional.isEmpty()) {
            throw new ResourceNotFoundException("Product not found");
        }

        Bid winningBid = biddingRepository.findByProductIdAndIsWinningBidTrue(productId);
        if (winningBid == null) {
            throw new ResourceNotFoundException("Product does not have a winning bid yet");
        }

        return modelMapper.map(winningBid, BidListDto.class);
    }

    @Override
    public void closeBidding(Long productId) {
        Optional<Product> productOptional = productRepository.findById(productId);
        if (productOptional.isEmpty()) {
            throw new ResourceNotFoundException("Product not found");
        }

        Product product = productOptional.get();
        product.setBiddingClosed(true);
        productRepository.save(product);

        // notify all bidders that bidding has closed
        List<UserEntity> bidders = biddingRepository.findDistinctBiddersByProductId(productId);
        if (bidders.isEmpty()) {
            return;
        }
        bidders.forEach(bidder -> notificationService.sendNotification(
                "Bidding has closed for " + product.getName(), bidder.getId()));
    }

    @Override
    public void reopenBidding(Long productId) {
        Optional<Product> productOptional = productRepository.findById(productId);
        if (productOptional.isEmpty()) {
            throw new ResourceNotFoundException("Product not found");
        }

        Product product = productOptional.get();

        // if product already has a winner bidding is not allowed
        if (product.getWinningBidder() != null) {
            throw new ValidationException("Product already has a winner, bidding is not allowed");
        }

        product.setBiddingClosed(false);
        productRepository.save(product);

        // notify all bidders that bidding has reopened
        List<UserEntity> biddingList = biddingRepository.findDistinctBiddersByProductId(productId);
        if (biddingList.isEmpty()) {
            return;
        }
        biddingList.forEach(bidder -> notificationService.sendNotification(
                "Bidding has reopened for " + product.getName(), bidder.getId()));
    }

    @Override
    public void declareWinner(Long productId) {
        Optional<Product> productOptional = productRepository.findById(productId);
        if (productOptional.isEmpty()) {
            throw new ResourceNotFoundException("Product not found");
        }

        Product product = productOptional.get();
        List<Bid> biddingList = biddingRepository.findBidsByProductIdOrderByBidAmountDesc(productId);

        // if no user has placed a bid on the product close bidding for that product
        if (biddingList.isEmpty()) {
            closeBidding(productId);
            return;
        }

        Bid winningBid = biddingList.get(0);
        UserEntity winner = winningBid.getBidder();

        winningBid.setIsWinningBid(true);
        product.setWinningBidder(winner);
        product.setBiddingClosed(true);
        productRepository.save(product);
        biddingRepository.save(winningBid);

        notificationService.sendNotification("🎉 Congratulations! You have won " + product.getName(), winner.getId());

        // notify user via email that they won the bid
        emailService.sendEmail(winner.getEmail(), "Congratulations! You have won the bid",
                "You have won the bid on " + product.getName() + " with a bid amount of " + winningBid.getBidAmount() + " go check it out!");

        List<Bid> losingBids = biddingRepository.findByProductIdAndIsWinningBidFalseAndBidderNot(productId, winner);

        for (Bid bid : losingBids) {
            notificationService.sendNotification(
                    "😞 You lost the bid on " + product.getName() + " to " + winner.getUsername(),
                    bid.getBidder().getId()
            );
        }
    }

    @Scheduled(fixedRate = 60000)
    public void checkBiddingStatus() {
        List<Product> products = productRepository.findAll();
        for (Product product : products) {
            if (product.isBiddingClosed()) {
                continue;
            }

            if (product.getEndTime().getTime() <= System.currentTimeMillis() && !product.isBiddingClosed()) {
                declareWinner(product.getId());
            }
        }
    }
}
